// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use bootlib::kernel_launch::KernelLaunchInfo;
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use svsm::address::{Address, PhysAddr, VirtAddr};
#[cfg(feature = "attest")]
use svsm::attest::AttestationDriver;
use svsm::config::SvsmConfig;
use svsm::console::install_console_logger;
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::gdt::GLOBAL_GDT;
use svsm::cpu::idt::svsm::{early_idt_init, idt_init};
use svsm::cpu::percpu::{this_cpu, PerCpu};
use svsm::cpu::shadow_stack::{
    determine_cet_support, is_cet_ss_supported, SCetFlags, MODE_64BIT, S_CET,
};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::cpu::sse::sse_init;
use svsm::debug::gdbstub::svsm_gdbstub::{debug_break, gdbstub_start};
use svsm::debug::stacktrace::print_stack;
use svsm::enable_shadow_stacks;
use svsm::fs::{initialize_fs, opendir, populate_ram_fs};
use svsm::fw_cfg::FwCfg;
use svsm::igvm_params::IgvmParams;
use svsm::kernel_region::new_kernel_region;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::memory::init_memory_map;
use svsm::mm::pagetable::paging_init;
use svsm::mm::virtualrange::virt_log_usage;
use svsm::mm::{init_kernel_mapping_info, FixedAddressMappingRange};
use svsm::platform;
use svsm::platform::{init_platform_type, SvsmPlatformCell, SVSM_PLATFORM};
use svsm::requests::{request_loop, request_processing_main};
use svsm::sev::secrets_page_mut;
use svsm::svsm_paging::{init_page_table, invalidate_early_boot_memory};
use svsm::task::exec_user;
use svsm::task::{schedule_init, start_kernel_task};
use svsm::types::PAGE_SIZE;
use svsm::utils::{immut_after_init::ImmutAfterInitCell, zero_mem_region};
#[cfg(all(feature = "vtpm", not(test)))]
use svsm::vtpm::vtpm_init;

use svsm::mm::validate::{init_valid_bitmap_ptr, migrate_valid_bitmap};

use alloc::string::String;

extern "C" {
    pub static bsp_stack_end: u8;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %r8  Pointer to the KernelLaunchInfo structure
 * %r9  Pointer to the valid-bitmap from stage2
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl  startup_64
    startup_64:
        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Jump to rust code */
        movq    %r8, %rdi
        movq    %r9, %rsi
        jmp svsm_start

        .bss

        .align {PAGE_SIZE}
    bsp_stack:
        .fill 8*{PAGE_SIZE}, 1, 0
    bsp_stack_end:
        "#,
    PAGE_SIZE = const PAGE_SIZE,
    options(att_syntax)
);

static CPUID_PAGE: ImmutAfterInitCell<SnpCpuidTable> = ImmutAfterInitCell::uninit();
static LAUNCH_INFO: ImmutAfterInitCell<KernelLaunchInfo> = ImmutAfterInitCell::uninit();

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    root_mem_init(
        PhysAddr::from(launch_info.heap_area_phys_start),
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_size as usize / PAGE_SIZE,
    );
}

pub fn boot_stack_info() {
    // SAFETY: this is only unsafe because `bsp_stack_end` is an extern
    // static, but we're simply printing its address. We are not creating a
    // reference so this is safe.
    let vaddr = VirtAddr::from(&raw const bsp_stack_end);
    log::info!("Boot stack starts        @ {:#018x}", vaddr);
}

fn mapping_info_init(launch_info: &KernelLaunchInfo) {
    let kernel_mapping = FixedAddressMappingRange::new(
        VirtAddr::from(launch_info.heap_area_virt_start),
        VirtAddr::from(launch_info.heap_area_virt_end()),
        PhysAddr::from(launch_info.heap_area_phys_start),
    );
    init_kernel_mapping_info(kernel_mapping, None);
}

/// # Panics
///
/// Panics if the provided address is not aligned to a [`SnpCpuidTable`].
fn init_cpuid_table(addr: VirtAddr) {
    // SAFETY: this is called from the main function for the SVSM and no other
    // CPUs have been brought up, so the pointer cannot be aliased.
    // `aligned_mut()` will check alignment for us.
    let table = unsafe {
        addr.aligned_mut::<SnpCpuidTable>()
            .expect("Misaligned SNP CPUID table address")
    };

    for func in table.func.iter_mut().take(table.count as usize) {
        if func.eax_in == 0x8000001f {
            func.eax_out |= 1 << 28;
        }
    }

    CPUID_PAGE
        .init(table)
        .expect("Already initialized CPUID page");
    register_cpuid_table(&CPUID_PAGE);
}

#[no_mangle]
pub extern "C" fn svsm_start(li: &KernelLaunchInfo, vb_addr: usize) {
    let launch_info: KernelLaunchInfo = *li;
    init_platform_type(launch_info.platform_type);

    let vb_ptr = core::ptr::NonNull::new(VirtAddr::new(vb_addr).as_mut_ptr::<u64>()).unwrap();

    mapping_info_init(&launch_info);

    // SAFETY: we trust the previous stage to pass a valid pointer
    unsafe { init_valid_bitmap_ptr(new_kernel_region(&launch_info), vb_ptr) };

    GLOBAL_GDT.load();
    GLOBAL_GDT.load_selectors();
    early_idt_init();

    // Capture the debug serial port before the launch info disappears from
    // the address space.
    let debug_serial_port = li.debug_serial_port;

    LAUNCH_INFO
        .init(li)
        .expect("Already initialized launch info");

    let mut platform = SvsmPlatformCell::new(li.platform_type);

    init_cpuid_table(VirtAddr::from(launch_info.cpuid_page));

    let secrets_page_virt = VirtAddr::from(launch_info.secrets_page);

    // SAFETY: the secrets page address directly comes from IGVM.
    // We trust stage 2 to give the value provided by IGVM.
    unsafe {
        secrets_page_mut().copy_from(secrets_page_virt);
        zero_mem_region(secrets_page_virt, secrets_page_virt + PAGE_SIZE);
    }

    cr0_init();
    cr4_init(&*platform);
    determine_cet_support();

    install_console_logger("SVSM").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    memory_init(&launch_info);
    migrate_valid_bitmap().expect("Failed to migrate valid-bitmap");

    let kernel_elf_len = (launch_info.kernel_elf_stage2_virt_end
        - launch_info.kernel_elf_stage2_virt_start) as usize;
    let kernel_elf_buf_ptr = launch_info.kernel_elf_stage2_virt_start as *const u8;
    // SAFETY: we trust stage 2 to pass on a correct pointer and length. This
    // cannot be aliased because we are on CPU 0 and other CPUs have not been
    // brought up. The resulting slice is &[u8], so there are no alignment
    // requirements.
    let kernel_elf_buf = unsafe { slice::from_raw_parts(kernel_elf_buf_ptr, kernel_elf_len) };
    let kernel_elf = match elf::Elf64File::read(kernel_elf_buf) {
        Ok(kernel_elf) => kernel_elf,
        Err(e) => panic!("error reading kernel ELF: {}", e),
    };

    paging_init(&*platform).expect("Failed to initialize paging");
    let init_pgtable =
        init_page_table(&launch_info, &kernel_elf).expect("Could not initialize the page table");
    // SAFETY: we are initializing the state, including stack and registers
    unsafe {
        init_pgtable.load();
    }

    let bsp_percpu = PerCpu::alloc(0).expect("Failed to allocate BSP per-cpu data");

    bsp_percpu
        .setup(&*platform, init_pgtable)
        .expect("Failed to setup BSP per-cpu area");
    bsp_percpu
        .setup_on_cpu(&*platform)
        .expect("Failed to run percpu.setup_on_cpu()");
    bsp_percpu.load();

    if is_cet_ss_supported() {
        enable_shadow_stacks!(bsp_percpu);
    }

    initialize_fs();

    // Idle task must be allocated after PerCPU data is mapped
    bsp_percpu
        .setup_idle_task(svsm_main)
        .expect("Failed to allocate idle task for BSP");

    idt_init();
    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    dump_cpuid_table();

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    let bp = this_cpu().get_top_of_stack();
    log::info!("BSP Runtime stack starts @ {:#018x}", bp);

    platform
        .configure_alternate_injection(launch_info.use_alternate_injection)
        .expect("Alternate injection required but not available");

    SVSM_PLATFORM
        .init(&platform)
        .expect("Failed to initialize SVSM platform object");

    sse_init();
    schedule_init();

    panic!("SVSM entry point terminated unexpectedly");
}

#[no_mangle]
pub extern "C" fn svsm_main() {
    // If required, the GDB stub can be started earlier, just after the console
    // is initialised in svsm_start() above.
    gdbstub_start(&**SVSM_PLATFORM).expect("Could not start GDB stub");
    // Uncomment the line below if you want to wait for
    // a remote GDB connection
    //debug_break();

    SVSM_PLATFORM
        .env_setup_svsm()
        .expect("SVSM platform environment setup failed");

    let launch_info = &*LAUNCH_INFO;
    let config = if launch_info.igvm_params_virt_addr != 0 {
        let igvm_params = IgvmParams::new(VirtAddr::from(launch_info.igvm_params_virt_addr))
            .expect("Invalid IGVM parameters");
        if (launch_info.vtom != 0) && (launch_info.vtom != igvm_params.get_vtom()) {
            panic!("Launch VTOM does not match VTOM from IGVM parameters");
        }
        SvsmConfig::IgvmConfig(igvm_params)
    } else {
        SvsmConfig::FirmwareConfig(FwCfg::new(SVSM_PLATFORM.get_io_port()))
    };

    init_memory_map(&config, &LAUNCH_INFO).expect("Failed to init guest memory map");

    populate_ram_fs(LAUNCH_INFO.kernel_fs_start, LAUNCH_INFO.kernel_fs_end)
        .expect("Failed to unpack FS archive");

    invalidate_early_boot_memory(&**SVSM_PLATFORM, &config, launch_info)
        .expect("Failed to invalidate early boot memory");

    let cpus = config.load_cpu_info().expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for cpu in cpus.iter() {
        if cpu.enabled {
            nr_cpus += 1;
        }
    }

    log::info!("{} CPU(s) present", nr_cpus);

    start_secondary_cpus(&**SVSM_PLATFORM, &cpus);

    if let Err(e) = SVSM_PLATFORM.prepare_fw(&config, new_kernel_region(&LAUNCH_INFO)) {
        panic!("Failed to prepare guest FW: {e:#?}");
    }

    #[cfg(feature = "attest")]
    {
        let mut attest_driver = AttestationDriver::try_from(kbs_types::Tee::Snp).unwrap();

        let secret = attest_driver.attest().unwrap();

        let msg = core::str::from_utf8(&secret).unwrap();
        log::info!("Decrypted vTPM state from attestation server: {:?}", msg);

        #[cfg(all(feature = "vtpm", not(test)))]
        vtpm_init(Some(secret)).expect("vTPM failed to initialize");
    }


    virt_log_usage();

    if let Err(e) = SVSM_PLATFORM.launch_fw(&config) {
        panic!("Failed to launch FW: {e:#?}");
    }

    start_kernel_task(request_processing_main, String::from("request-processing"))
        .expect("Failed to launch request processing task");

    #[cfg(test)]
    crate::test_main();

    match exec_user("/init", opendir("/").expect("Failed to find FS root")) {
        Ok(_) => (),
        Err(e) => log::info!("Failed to launch /init: {e:#?}"),
    }

    request_loop();

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    secrets_page_mut().clear_vmpck(0);
    secrets_page_mut().clear_vmpck(1);
    secrets_page_mut().clear_vmpck(2);
    secrets_page_mut().clear_vmpck(3);

    log::error!("Panic: CPU[{}] {}", this_cpu().get_apic_id(), info);

    print_stack(3);

    loop {
        debug_break();
        platform::halt();
    }
}
