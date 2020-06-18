/*
 * Simple VM encapsulation layer on top of libwhp.
 *
 * Much of the code is borrowed from the demo example from libwhp as currently found here:
 * https://github.com/insula-rs/libwhp/blob/master/examples/demo.rs
 */

extern crate libwhp;

use std;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::RwLock;
use std::thread;

use libwhp::instruction_emulator::*;
use libwhp::memory::*;
use libwhp::*;

const PDE64_PRESENT: u64 = 1;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

const PAGE_SIZE: u64 = 0x1000;
const PTE_FRAME_BIT_OFFSET: u64 = 12;
const PTE_FRAME_MASK: u64 = 0xF_FFFFFFFF;

const PTE_PML4E_OFFSET: u64 = 39;
const PTE_PML4E_MASK: u64 = 0x1ff;

const PTE_PDPTE_OFFSET: u64 = 30;
const PTE_PDPTE_MASK: u64 = 0x1ff;

const PTE_PDE_OFFSET: u64 = 21;
const PTE_PDE_MASK: u64 = 0x1ff;

const PTE_PTE_OFFSET: u64 = 12;
const PTE_PTE_MASK: u64 = 0x1ff;

fn pte_get_physical_address(pte: u64) -> u64 {
    ((pte >> PTE_FRAME_BIT_OFFSET) & PTE_FRAME_MASK) * PAGE_SIZE
}

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const INT_VECTOR: u32 = 0x35;

#[derive(Clone)]
pub struct VirtualMachineConfig {
    pub processor_count: u32,
    pub memory_layout: MemoryLayout
}

pub struct VirtualMachine {
    pub vm_id: usize,
    pub vm_config: VirtualMachineConfig,
    partition: Partition,
    apic_enabled: bool,
    apic_present: bool,
    pub virtual_processors: Vec<Arc<RwLock<VirtualProcessorExtension>>>,
    physical_memory_map: Vec<PhysicalMemoryMapping>,
    pml4_addr: u64,
}

struct VirtualMachineCallbacks<'a> {
    vpe_rwlock: &'a RwLock<VirtualProcessorExtension>,
}

pub struct VirtualProcessorExtension {
    pub vp: VirtualProcessor,
    pub last_exit_context: WHV_RUN_VP_EXIT_CONTEXT,
}

#[derive(Clone)]
pub enum MemoryProtection {
    Read,
    ReadWrite,
    ReadWriteExecute
}

#[derive(Copy, Clone, PartialEq)]
pub enum MemoryRegionType {
    PageTables,
    Code,
    Data,
    Stack
}

#[derive(Clone)]
pub struct PhysicalMemoryRange {
    pub base_address: u64,
    pub region_size: usize,
    pub ept_protection: MemoryProtection,
    pub region_type: MemoryRegionType
}

pub struct PhysicalMemoryMapping {
    pub physical_map: GPARangeMapping,
    pub host_virtual_map: VirtualMemory,
    pub region_type: MemoryRegionType,
    pub allocated_page_map: Vec<bool>
}

#[derive(Clone)]
pub struct MemoryDescriptor {
    pub physical_address: u64,
    pub virtual_protection: MemoryProtection
}

#[derive(Clone)]
pub struct VirtualMemoryDescriptor {
    pub base_address: u64,
    pub region_type: MemoryRegionType,
    pub memory_descriptors: Vec<MemoryDescriptor>
}

impl VirtualMemoryDescriptor {
    pub fn get_region_size(&self) -> usize {
        (self.memory_descriptors.len() * PAGE_SIZE as usize) as usize
    }
}

#[derive(Clone)]
pub struct MemoryLayout {
    pub physical_layout: Vec<PhysicalMemoryRange>,
    pub virtual_layout: Vec<VirtualMemoryDescriptor>,
}

impl<'a> VirtualMachine {
    pub fn new(vm_id: usize, vm_config: VirtualMachineConfig) -> VirtualMachine {
        // Verify that the hypervisor is present
        let capability =
            get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent).unwrap();

        if unsafe { capability.HypervisorPresent } == FALSE {
            panic!("Hypervisor not present");
        }

        // Check if APIC is present
        let capability = get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
        let features: WHV_CAPABILITY_FEATURES = unsafe { capability.Features };

        let processor_count = vm_config.processor_count;

        VirtualMachine {
            vm_id: vm_id,
            vm_config: vm_config,
            partition: Partition::new().unwrap(),
            apic_enabled: false,
            apic_present: features.LocalApicEmulation() != 0,
            virtual_processors: Vec::with_capacity(processor_count as usize),
            physical_memory_map: Vec::new(),
            pml4_addr: 0
        }
    }

    pub fn setup(&mut self) {
        // Set the processor count for the VM
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = self.vm_config.processor_count;
        self.partition
            .set_property(
                WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
                &property,
            )
            .unwrap();

        // Set the extended VM exits for the VM
        property = Default::default();
        unsafe {
            property.ExtendedVmExits.set_X64CpuidExit(1);
            property.ExtendedVmExits.set_X64MsrExit(1);
            property.ExtendedVmExits.set_ExceptionExit(1);
        }

        self.partition
            .set_property(
                WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeExtendedVmExits,
                &property,
            )
            .unwrap();

        let cpuids: [UINT32; 1] = [1];
        self.partition.set_property_cpuid_exits(&cpuids).unwrap();

        let mut cpuid_results: [WHV_X64_CPUID_RESULT; 1] = Default::default();

        cpuid_results[0].Function = 0x40000000;
        let mut id_reg_values: [UINT32; 3] = [0; 3];
        let id = "cpufuzz\0";
        unsafe {
            std::ptr::copy_nonoverlapping(
                id.as_ptr(),
                id_reg_values.as_mut_ptr() as *mut u8,
                id.len(),
            );
        }
        cpuid_results[0].Ebx = id_reg_values[0];
        cpuid_results[0].Ecx = id_reg_values[1];
        cpuid_results[0].Edx = id_reg_values[2];

        self.partition
            .set_property_cpuid_results(&cpuid_results)
            .unwrap();

        // Enable APIC if present for the VM
        if self.apic_present != false {
            self.enable_apic();
        }

        // Set up the partition itself
        self.partition.setup().unwrap();

        // Setup the backing physical memory for the VM
        self.setup_physical_memory();

        // Setup the virtual processors for the VM
        self.setup_virtual_processors();
    }

    pub fn execute(&self, completion: Arc<(std::sync::Mutex<bool>, Condvar)>) {
        let mut threads: Vec<thread::JoinHandle<_>> = Vec::new();

        for vpe_rwlock in self.virtual_processors.iter() {
            if self.apic_enabled {
                self.set_apic_base(&mut vpe_rwlock.write().unwrap().vp);
                self.send_ipi(&mut vpe_rwlock.write().unwrap().vp, INT_VECTOR);
                self.set_delivery_notifications(&mut vpe_rwlock.write().unwrap().vp);
            }

            let thread_vpe = vpe_rwlock.clone();
            let thread_completion = completion.clone();
            let thread = thread::spawn(move || {
                VirtualMachine::execute_vp(&thread_vpe);

                let (lock, cvar) = &*thread_completion;
                let mut done = lock.lock().unwrap();
                *done = true;
                cvar.notify_all();
            });

            threads.push(thread);
        }
    }

    fn execute_vp(vpe_rwlock: &Arc<RwLock<VirtualProcessorExtension>>) {
        let _callbacks = VirtualMachineCallbacks {
            vpe_rwlock: vpe_rwlock,
        };

        let _emulator = Emulator::<VirtualMachineCallbacks>::new().unwrap();

        loop {
            let exit_context: WHV_RUN_VP_EXIT_CONTEXT;

            {
                let vpe = vpe_rwlock.read().unwrap();

                exit_context = vpe.vp.run().unwrap();
            }

            {
                let mut vpe = vpe_rwlock.write().unwrap();

                vpe.last_exit_context = exit_context;
            }

            match exit_context.ExitReason {
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnrecoverableException => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonCanceled => {
                    break;
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonInvalidVpRegisterValue => {
                    break;
                }
                _ => panic!("Unexpected exit type: {:?}", exit_context.ExitReason),
            };
        }
    }

    fn setup_physical_memory(&mut self) {
        for physical_region in &self.vm_config.memory_layout.physical_layout {
            let virtual_map = VirtualMemory::new(physical_region.region_size)
                .expect("virtual memory mapping failed");

            let physical_map_res =  self.partition.map_gpa_range(
                &virtual_map,
                physical_region.base_address,
                physical_region.region_size as UINT64,
                match physical_region.ept_protection {
                    MemoryProtection::Read =>  {
                        WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                    },
                    MemoryProtection::ReadWrite => {
                        WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                        | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                    },
                    MemoryProtection::ReadWriteExecute => {
                        WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                        | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                        | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagExecute
                    }
                }
            );

            let physical_map = match physical_map_res {
                Ok(physical_map) => {
                    physical_map
                },
                Err(err) => {
                    panic!("map_gpa_range failed with {}", err);
                }
            };

            self.physical_memory_map.push(PhysicalMemoryMapping {
                host_virtual_map: virtual_map,
                physical_map: physical_map,
                region_type: physical_region.region_type,
                allocated_page_map: Vec::new()
            })
        }
    }

    pub fn get_physical_memory_slice_mut(
        &'a mut self,
        physical_address: usize,
        length: usize,
    ) -> &'a mut [u8] {
        for physical_mapping in &mut self.physical_memory_map {
            let mapping_base_address = physical_mapping.physical_map.get_guest_address() as usize;
            let mapping_size = physical_mapping.physical_map.get_size() as usize;

            if physical_address >= mapping_base_address
                && physical_address < mapping_base_address + mapping_size {
                let s = physical_mapping.host_virtual_map.as_slice_mut();

                let offset = physical_address - mapping_base_address;

                return &mut s[offset..(offset+length)];
            }
        }

        panic!("failed to find gpa {:X}", physical_address);
    }

    pub fn get_physical_memory_slice(&'a self, physical_address: usize, length: usize) -> &'a [u8] {
        for physical_mapping in &self.physical_memory_map {
            let mapping_base_address = physical_mapping.physical_map.get_guest_address() as usize;
            let mapping_size = physical_mapping.physical_map.get_size() as usize;

            if physical_address >= mapping_base_address
                && physical_address < mapping_base_address + mapping_size {
                let s = physical_mapping.host_virtual_map.as_slice();

                let offset = physical_address - mapping_base_address;

                return &s[offset..(offset+length)];
            }
        }

        panic!("failed to find gpa {:X}", physical_address);
    }

    fn get_virtual_region_by_type(&'a self, region_type: MemoryRegionType) -> &'a VirtualMemoryDescriptor {
        for virtual_memory_desc in &self.vm_config.memory_layout.virtual_layout {
            if virtual_memory_desc.region_type == region_type {
                return &virtual_memory_desc;
            }
        }

        panic!("failed to find region type");
    }

    fn initialize_address_space(& mut self) -> u64 {

        let mut host_page_table_map_opt = None;

        for map in &mut self.physical_memory_map {
            if map.region_type == MemoryRegionType::PageTables {
                host_page_table_map_opt = Some(map);
                break;
            }
        }

        if host_page_table_map_opt.is_none() {
            panic!("failed to find page table mapping");
        }

        let host_page_table_map = host_page_table_map_opt.unwrap();
        let max_page_table_pages = host_page_table_map.host_virtual_map.get_size() / (PAGE_SIZE as usize);

        host_page_table_map.allocated_page_map = vec! [false; max_page_table_pages];

        let page_table_base_gpa = host_page_table_map.physical_map.get_guest_address();
        let page_table_base_hptr = host_page_table_map.host_virtual_map.as_ptr() as u64;
       
        // Allocate the PML4 page
        let pml4_base_gpa = allocate_gpa(host_page_table_map);
        let pml4_base_hptr = page_table_base_hptr + (pml4_base_gpa - page_table_base_gpa);

        for virtual_memory_desc in &self.vm_config.memory_layout.virtual_layout {

            let mut virtual_address = virtual_memory_desc.base_address;

            for memory_desc in &virtual_memory_desc.memory_descriptors {

                // PML4E lookup
                let pml4e_hptr = pml4_base_hptr + (((virtual_address >> PTE_PML4E_OFFSET) & PTE_PML4E_MASK) * 8);
                let pml4e = unsafe { *(pml4e_hptr as *mut u64) };

                let pdpt_base_gpa;
                if pml4e == 0 {
                    pdpt_base_gpa = allocate_gpa(host_page_table_map);

                    let pdpt_base_pfn = pdpt_base_gpa / PAGE_SIZE;

                    unsafe { *(pml4e_hptr as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | (pdpt_base_pfn << PTE_FRAME_BIT_OFFSET) };
                } else {
                    pdpt_base_gpa = pte_get_physical_address(pml4e);
                }
        
                // PDPTE lookup
                let pdpt_base_hptr = page_table_base_hptr + (pdpt_base_gpa - page_table_base_gpa);
                let pdpte_htpr = pdpt_base_hptr + (((virtual_address >> PTE_PDPTE_OFFSET) & PTE_PDPTE_MASK) * 8);
                let pdpte = unsafe { *(pdpte_htpr as *mut u64) };
                
                let pde_base_gpa: u64;
                if pdpte == 0 {
                    pde_base_gpa = allocate_gpa(host_page_table_map);

                    let pde_base_pfn = pde_base_gpa / PAGE_SIZE;

                    unsafe { *(pdpte_htpr as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | (pde_base_pfn << PTE_FRAME_BIT_OFFSET) };
                } else {
                    pde_base_gpa = pte_get_physical_address(pdpte);
                }
                
                // PDE lookup
                let pde_base_hptr = page_table_base_hptr + (pde_base_gpa - page_table_base_gpa);
                let pde_hptr = pde_base_hptr + (((virtual_address >> PTE_PDE_OFFSET) & PTE_PDE_MASK) * 8);
                let pde = unsafe { *(pde_hptr as *mut u64) };

                let pte_base_gpa: u64;
                if pde == 0 {
                    pte_base_gpa = allocate_gpa(host_page_table_map);

                    let pte_base_pfn = pte_base_gpa / PAGE_SIZE;

                    unsafe { *(pde_hptr as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | (pte_base_pfn << PTE_FRAME_BIT_OFFSET) };
                } else {
                    pte_base_gpa = pte_get_physical_address(pde);
                }

                // PTE initialization
                let pte_base_hptr = page_table_base_hptr + (pte_base_gpa - page_table_base_gpa);
                let pte_hptr = pte_base_hptr + (((virtual_address >> PTE_PTE_OFFSET) & PTE_PTE_MASK) * 8);

                let mut pte_value = PDE64_PRESENT | PDE64_RW | PDE64_USER;
                pte_value |= (memory_desc.physical_address / PAGE_SIZE) << PTE_FRAME_BIT_OFFSET;

                match memory_desc.virtual_protection {
                    MemoryProtection::Read
                    | MemoryProtection::ReadWrite => {
                        pte_value |= 1 << 63; // NX bit
                    },
                    _ => {}
                }
                
                unsafe { *(pte_hptr as *mut u64) = pte_value };

                // Proceed to the next virtual address.
                virtual_address += PAGE_SIZE;
            }
        }

        pml4_base_gpa
    }

    fn setup_virtual_processors(&mut self) {
        for vp_index in 0..self.vm_config.processor_count {
            self.setup_virtual_processor(vp_index);
        }
    }

    fn setup_virtual_processor(&mut self, vp_index: u32) {
        let mut vp = self.partition.create_virtual_processor(vp_index).unwrap();

        self.pml4_addr = self.initialize_address_space();

        // Setup long mode for this VP
        self.set_initial_registers(&mut vp, 0, 0);

        // Configure the APIC
        self.setup_apic(&mut vp);

        let vpe_rwlock = RwLock::new(VirtualProcessorExtension {
            vp: vp,
            last_exit_context: Default::default(),
        });

        self.virtual_processors.push(Arc::new(vpe_rwlock));
    }

    pub fn set_initial_registers(&self, vp: &mut VirtualProcessor, gpr_default_value: u64, initial_rip: u64) {
        const NUM_REGS: UINT32 = 28;
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

        // Initialize control registers with protected mode enabled but paging disabled initially.
        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
        reg_values[0].Reg64 = self.pml4_addr;
        reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
        reg_values[1].Reg64 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;

        reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterCr0;
        reg_values[2].Reg64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
        reg_names[3] = WHV_REGISTER_NAME::WHvX64RegisterEfer;
        reg_values[3].Reg64 = EFER_LME | EFER_LMA;

        reg_names[4] = WHV_REGISTER_NAME::WHvX64RegisterCs;
        unsafe {
            let segment = &mut reg_values[4].Segment;
            segment.Base = 0;
            segment.Limit = 0xffffffff;
            segment.Selector = 1 << 3;
            segment.set_SegmentType(11);
            segment.set_NonSystemSegment(1);
            segment.set_Present(1);
            segment.set_Long(1);
            segment.set_Granularity(1);
        }

        reg_names[5] = WHV_REGISTER_NAME::WHvX64RegisterDs;
        unsafe {
            let segment = &mut reg_values[5].Segment;
            segment.Base = 0;
            segment.Limit = 0xffffffff;
            segment.Selector = 2 << 3;
            segment.set_SegmentType(3);
            segment.set_NonSystemSegment(1);
            segment.set_Present(1);
            segment.set_Long(1);
            segment.set_Granularity(1);
        }

        reg_names[6] = WHV_REGISTER_NAME::WHvX64RegisterEs;
        reg_values[6] = reg_values[5];

        reg_names[7] = WHV_REGISTER_NAME::WHvX64RegisterFs;
        reg_values[7] = reg_values[5];

        reg_names[8] = WHV_REGISTER_NAME::WHvX64RegisterGs;
        reg_values[8] = reg_values[5];

        reg_names[9] = WHV_REGISTER_NAME::WHvX64RegisterSs;
        reg_values[9] = reg_values[5];

        // Start with the Interrupt Flag off; guest will enable it when ready
        reg_names[10] = WHV_REGISTER_NAME::WHvX64RegisterRflags;
        reg_values[10].Reg64 = 0x0002;

        reg_names[11] = WHV_REGISTER_NAME::WHvX64RegisterRip;
        reg_values[11].Reg64 = initial_rip;

        // Create stack with stack base at high end of mapped payload
        reg_names[12] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
        let stack_region = self.get_virtual_region_by_type(MemoryRegionType::Stack);
        reg_values[12].Reg64 = stack_region.base_address + stack_region.get_region_size() as UINT64;

        reg_names[13] = WHV_REGISTER_NAME::WHvX64RegisterRax;
        reg_values[13].Reg64 = gpr_default_value;
        reg_names[14] = WHV_REGISTER_NAME::WHvX64RegisterRbx;
        reg_values[14].Reg64 = gpr_default_value;
        reg_names[15] = WHV_REGISTER_NAME::WHvX64RegisterRcx;
        reg_values[15].Reg64 = gpr_default_value;
        reg_names[16] = WHV_REGISTER_NAME::WHvX64RegisterRdx;
        reg_values[16].Reg64 = gpr_default_value;
        reg_names[17] = WHV_REGISTER_NAME::WHvX64RegisterRdi;
        reg_values[17].Reg64 = gpr_default_value;
        reg_names[18] = WHV_REGISTER_NAME::WHvX64RegisterRsi;
        reg_values[18].Reg64 = gpr_default_value;
        reg_names[19] = WHV_REGISTER_NAME::WHvX64RegisterRbp;
        reg_values[19].Reg64 = gpr_default_value;
        reg_names[20] = WHV_REGISTER_NAME::WHvX64RegisterR8;
        reg_values[20].Reg64 = gpr_default_value;
        reg_names[21] = WHV_REGISTER_NAME::WHvX64RegisterR9;
        reg_values[22].Reg64 = gpr_default_value;
        reg_names[22] = WHV_REGISTER_NAME::WHvX64RegisterR10;
        reg_values[22].Reg64 = gpr_default_value;
        reg_names[23] = WHV_REGISTER_NAME::WHvX64RegisterR11;
        reg_values[23].Reg64 = gpr_default_value;
        reg_names[24] = WHV_REGISTER_NAME::WHvX64RegisterR12;
        reg_values[24].Reg64 = gpr_default_value;
        reg_names[25] = WHV_REGISTER_NAME::WHvX64RegisterR13;
        reg_values[25].Reg64 = gpr_default_value;
        reg_names[26] = WHV_REGISTER_NAME::WHvX64RegisterR14;
        reg_values[26].Reg64 = gpr_default_value;
        reg_names[27] = WHV_REGISTER_NAME::WHvX64RegisterR15;
        reg_values[27].Reg64 = gpr_default_value;

        // Create stack with stack base at high end of mapped payload
        vp.set_registers(&reg_names, &reg_values).unwrap();
    }

    fn enable_apic(&mut self) {
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.LocalApicEmulationMode =
            WHV_X64_LOCAL_APIC_EMULATION_MODE::WHvX64LocalApicEmulationModeXApic;

        self.partition
            .set_property(
                WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeLocalApicEmulationMode,
                &property,
            )
            .unwrap();

        self.apic_enabled = true;
    }

    fn set_apic_base(&self, vp: &mut VirtualProcessor) {
        // Page table translations for this guest only cover the first 1GB of memory,
        // and the default APIC base falls above that. Set the APIC base to
        // something lower, within our range of virtual memory

        // Get the default APIC base register value to start
        const NUM_REGS: usize = 1;
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;

        // Get the registers as a baseline
        vp.get_registers(&reg_names, &mut reg_values).unwrap();
        let mut flags = unsafe { reg_values[0].Reg64 };

        // Mask off the bottom 12 bits, which are used to store flags
        flags = flags & 0xfff;

        // Set the APIC base to something lower within our translatable address
        // space
        let new_apic_base = 0x0fee_0000;
        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;
        reg_values[0].Reg64 = new_apic_base | flags;
        vp.set_registers(&reg_names, &reg_values).unwrap();
    }

    fn send_msi(&self, vp: &mut VirtualProcessor, message: &WHV_MSI_ENTRY) {
        let addr: UINT32 = unsafe { message.anon_struct.Address };
        let data: UINT32 = unsafe { message.anon_struct.Data };

        let dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
        let vector = (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
        let dest_mode = (addr >> MSI_ADDR_DEST_MODE_SHIFT) & 0x1;
        let trigger_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
        let delivery = (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x7;

        let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

        interrupt.set_InterruptType(delivery as UINT64);

        if dest_mode == 0 {
            interrupt.set_DestinationMode(
                WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical as UINT64,
            );
        } else {
            interrupt.set_DestinationMode(
                WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModeLogical as UINT64,
            );
        }

        interrupt.set_TriggerMode(trigger_mode as UINT64);

        interrupt.Destination = dest;
        interrupt.Vector = vector;

        vp.request_interrupt(&mut interrupt).unwrap();
    }

    fn send_ipi(&self, vp: &mut VirtualProcessor, vector: u32) {
        let mut message: WHV_MSI_ENTRY = Default::default();

        // - Trigger mode is 'Edge'
        // - Interrupt type is 'Fixed'
        // - Destination mode is 'Physical'
        // - Destination is 0. Since Destination Mode is Physical, bits 56-59
        //   contain the APIC ID of the target processor (APIC ID = 0)
        // Level = 1 and Destination Shorthand = 1, but the underlying API will
        // actually ignore this.
        message.anon_struct.Data = (0x00044000 | vector) as UINT32;
        message.anon_struct.Address = 0;

        VirtualMachine::send_msi(self, vp, &message);
    }

    fn set_delivery_notifications(&self, vp: &mut VirtualProcessor) {
        const NUM_REGS: usize = 1;
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();

        let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER = Default::default();
        notifications.set_InterruptNotification(1);
        reg_values[0].DeliverabilityNotifications = notifications;
        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications;
        vp.set_registers(&reg_names, &reg_values).unwrap();
    }

    fn setup_apic(&self, vp: &mut VirtualProcessor) {
        self.send_ipi(vp, INT_VECTOR);

        const NUM_REGS: usize = 1;
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();

        let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER = Default::default();
        notifications.set_InterruptNotification(1);
        reg_values[0].DeliverabilityNotifications = notifications;
        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications;
        vp.set_registers(&reg_names, &reg_values).unwrap();
    }
}

impl<'a> EmulatorCallbacks for VirtualMachineCallbacks<'a> {
    fn io_port(&mut self, _io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO) -> HRESULT {
        S_OK
    }

    fn memory(&mut self, _memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO) -> HRESULT {
        S_OK
    }

    fn get_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vpe_rwlock
            .read()
            .unwrap()
            .vp
            .get_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn set_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &[WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vpe_rwlock
            .write()
            .unwrap()
            .vp
            .set_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn translate_gva_page(
        &mut self,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        let (translation_result1, gpa1) = self
            .vpe_rwlock
            .read()
            .unwrap()
            .vp
            .translate_gva(gva, translate_flags)
            .unwrap();
        *translation_result = translation_result1.ResultCode;
        *gpa = gpa1;
        S_OK
    }
}

fn allocate_gpa(mapping: &mut PhysicalMemoryMapping) -> u64 {

    let mut pfn = 0;
    let mut found_pfn = false;

    for entry in &mapping.allocated_page_map {
        if *entry == false {
            found_pfn = true;
            break;
        }

        pfn += 1;
    }

    if found_pfn == false {
        panic!("ran out of physical memory to allocate");
    }

    mapping.allocated_page_map[pfn] = true;

    mapping.physical_map.get_guest_address() + (pfn as u64 * PAGE_SIZE)
}