use maarch64_core::memory::{align_down_page, align_up_page, MemoryManager, PAGE_SIZE};

#[test]
fn test_page_alignment() {
    assert_eq!(align_down_page(0x400010), 0x400000);
    assert_eq!(align_up_page(0x400010), 0x401000);
    assert_eq!(align_down_page(0x400000), 0x400000);
    assert_eq!(align_up_page(0x400000), 0x400000);
}

#[test]
fn test_brk_dynamic_allocation() {
    let mut mem = MemoryManager::new();
    let initial_base = 0x600000;
    mem.set_brk_base(initial_base);

    assert_eq!(mem.brk_base, initial_base);
    assert_eq!(mem.brk_current, initial_base);

    // Expand brk
    let target_brk = initial_base + (PAGE_SIZE as u64) * 2;
    let new_brk = mem.set_brk(target_brk).unwrap();
    assert_eq!(new_brk, target_brk);

    // Verify write and read on newly allocated heap area
    let test_data = [0xde, 0xad, 0xbe, 0xef];
    mem.write(initial_base + 100, &test_data).unwrap();
    let read_back = mem.read(initial_base + 100, 4).unwrap();
    assert_eq!(read_back, &test_data);
}

#[test]
fn test_unmapped_access_error() {
    let mem = MemoryManager::new();
    assert!(mem.read(0x1000, 4).is_err());
}
