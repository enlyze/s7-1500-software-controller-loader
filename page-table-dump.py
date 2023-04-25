from gdb import Command, COMMAND_USER, COMPLETE_EXPRESSION, parse_and_eval, execute, Value, lookup_type, inferiors
from struct import pack


def to_unsigned_long(v):
    """Cast a gdb.Value to unsigned long."""
    mask = (1 << 64) - 1
    return int(v.cast(Value(mask).type)) & mask


class PageTableDumpCmd(Command):
    """Prints the ListNode from our example in a nice format!"""

    def __init__(self):
        super(PageTableDumpCmd, self).__init__(
            "page_table_dump", COMMAND_USER
        )

    def complete(self, text, word):
        return COMPLETE_EXPRESSION

    def print_entry(self, entry: int) -> int:
        physical_page_address = (entry & ((1 << 51) - 1)) & ~((1 << 11) - 1)

        flags = []
        if entry & 1:
            flags.append("PRESENT")
        if entry & 2:
            flags.append("WRITE")
        if entry & 4:
            flags.append("USERMODE")
        if entry & 8:
            flags.append("WRITETHROUGH")
        if entry & 16:
            flags.append("CACHE_DISABLE")
        if entry & 32:
            flags.append("ACCESSED")
        if entry & 64:
            flags.append("DIRTY")
        if entry & 128:
            flags.append("HUGE_SIZE")
        if entry & 256:
            flags.append("GLOBAL")
        if entry & (1 << 63):
            flags.append("NO_EXECUTE")

        available1 = (entry >> 9) & 7
        available2 = (entry >> 52) & 0x7ff

        print(hex(entry), hex(physical_page_address),
              flags, available1, available2)

        return Value(physical_page_address)

    def read_entry(self, ptr):
        i64 = lookup_type("unsigned long long")
        i64ptr = i64.pointer()
        lazy_ptrvalue = (ptr).cast(i64ptr)
        value = to_unsigned_long(lazy_ptrvalue.dereference())

        ptr = to_unsigned_long(ptr)
        inferiors()[0].write_memory(ptr, pack("<Q", 0), 8)
        zero = to_unsigned_long(lazy_ptrvalue.dereference())
        inferiors()[0].write_memory(ptr, pack("<Q", value), 8)
        assert zero == 0, zero
        assert value == to_unsigned_long(lazy_ptrvalue.dereference())

        return value

    def invoke(self, args, from_tty):
        addr = parse_and_eval(args)
        addr = to_unsigned_long(addr)

        bits = addr & ((1 << 48) - 1) & ~0xFFF
        print(hex(addr), hex(bits))

        p4 = bits >> 39
        p3 = (bits >> 30) & 0x1FF
        p2 = (bits >> 21) & 0x1FF
        p1 = (bits >> 12) & 0x1FF

        print(p4, p3, p2, p1)

        cr3 = parse_and_eval("$cr3")
        cr3num = to_unsigned_long(cr3)
        print("Cr3: " + hex(cr3num))

        assert cr3num & 0xFFF == 0

        execute("maintenance packet Qqemu.PhyMemMode:1", False, True)

        p4_entry = self.read_entry(cr3 + p4*8)
        table3 = self.print_entry(p4_entry)

        p3_entry = self.read_entry(table3 + p3*8)
        table2 = self.print_entry(p3_entry)

        p2_entry = self.read_entry(table2 + p2*8)
        table1 = self.print_entry(p2_entry)

        p1_entry = self.read_entry(table1 + p1*8)
        self.print_entry(p1_entry)

        execute("maintenance packet Qqemu.PhyMemMode:0", False, True)


PageTableDumpCmd()
