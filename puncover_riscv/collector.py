import fnmatch
import os
import re
import sys
import time

CANTFIX = "cantfix"
NAME = "name"
DISPLAY_NAME = "display_name"
SIZE = "size"
PATH = "path"
BASE_FILE = "base_file"
LINE = "line"
ASM = "asm"
STACK_SIZE = "stack_size"
STACK_QUALIFIERS = "stack_qualifiers"
ADDRESS = "address"
TYPE = "type"
TYPE_FUNCTION = "function"
TYPE_VARIABLE = "variable"
TYPE_FILE = "file"
TYPE_FOLDER = "folder"
PREV_FUNCTION = "prev_function"
NEXT_FUNCTION = "next_function"
FUNCTIONS = "functions"
VARIABLES = "variables"
SYMBOLS = "symbols"
INTERRUPT = "irq"
BIND = "bind"
SECTION = "section"
ALIGN = "align"
FLAG = "flag"
FILE = "file"
FILES = "files"
FOLDER = "folder"
ROOT = "root"
ANCESTORS = "ancestors"
SUB_FOLDERS = "sub_folders"
COLLAPSED_NAME = "collapsed_name"
COLLAPSED_SUB_FOLDERS = "collapsed_sub_folders"
CALLEES = "callees"
CALLERS = "callers"

DEEPEST_CALLEE_TREE = "deepest_callee_tree"
DEEPEST_CALLER_TREE = "deepest_caller_tree"


def warning(*objs):
    print("WARNING: ", *objs, file=sys.stderr)


def left_strip_from_list(lines):
    if len(lines) <= 0:
        return lines

    # detect longest common sequence of white spaces
    longest_match = re.match(r"^\s*", lines[0]).group(0)

    for line in lines:
        while not line.startswith(longest_match):
            longest_match = longest_match[:-1]

    # remove from each string
    return list([line[len(longest_match):] for line in lines])


class Collector:

    def __init__(self, gcc_tools):
        self.gcc_tools = gcc_tools
        self.section = {}
        self.symbols = {}
        self.file_elements = {}
        self.symbols_by_qualified_name = None
        self.symbols_by_name = None

    def reset(self):
        self.section = {}
        self.symbols = {}
        self.file_elements = {}
        self.symbols_by_qualified_name = None
        self.symbols_by_name = None

    def qualified_symbol_name(self, symbol):
        if BASE_FILE in symbol:
            return os.path.join(symbol[PATH], symbol[NAME])
        return symbol[NAME]

    def symbol(self, name, qualified=True):
        self.build_symbol_name_index()
        index = self.symbols_by_qualified_name if qualified else self.symbols_by_name
        return index.get(name, None)

    def symbol_by_addr(self, addr):
        int_addr = int(addr, 16)
        return self.symbols.get(int_addr, None)

    def symbol_create(self, name: str, address: str, type: str, size: int, sec: int, bind: str):
        int_address = int(address, 16)
        sym = self.symbols.get(int_address, {})
        if sym != {}:
            # warning(
            #     "skip creating symbol %s name %s type %s size %d\n                                    new name %s type %s size %d" %
            #     (sym[ADDRESS], sym[NAME], sym[TYPE], sym[SIZE], name, type, size))
            return sym

        sym[NAME] = name
        sym[SIZE] = size
        sym[TYPE] = type
        sym[SECTION] = sec
        sym[ADDRESS] = address
        sym[BIND] = bind
        if bind == "LOCAL":
            sym["local"] = True

        self.symbols[int_address] = sym
        return sym

    def symbol_add_file_line(self, address: int, name: str, file: str = None, line: int = None):
        sym = self.symbols.get(address, {})
        if sym == {}:
            return False
        if sym[NAME] != name:
            return False

        if file:
            sym[PATH] = file
            sym[BASE_FILE] = os.path.basename(file)
        if line:
            sym[LINE] = line

        self.symbols[address] = sym
        return sym

    def symbol_add_assembly(self, address: int, assembly=None):
        sym = self.symbols.get(address, {})
        if sym == {}:
            return False

        if not assembly:
            return False

        if sym[TYPE] == TYPE_FUNCTION:
            assembly = left_strip_from_list(assembly)
            sym[ASM] = assembly
            self.symbols[address] = sym
            return sym

        else:
            return False

    def symbol_add_stack_usage(self, file: str, line: int, name: str, stack: int, qualifier: str):
        samefile_symbols = [
            s for s in self.symbols.values() if s.get(PATH, None) == file]

        for sym in samefile_symbols:
            if sym.get(LINE, None) == line or self.display_names_match(name, sym.get(DISPLAY_NAME, None)):
                sym[STACK_SIZE] = stack
                sym[STACK_QUALIFIERS] = qualifier
                return True

        return False

    def symbol_add_function_call(self, caller, callee):
        if caller != callee:
            if not callee in caller[CALLEES]:
                caller[CALLEES].append(callee)
            if not caller in callee[CALLERS]:
                callee[CALLERS].append(caller)

    # parse group

    def parse_elf(self, elf_file):
        print("parsing ELF at %s" % elf_file)

        print("parsing sections ", end="")
        for l in self.gcc_tools.get_elf_section(elf_file):
            self.parse_elf_section(l)
        print("total %d" % len(self.section.values()))
        # for sec in self.section.values():
        #     print(sec)

        print("parsing symbols ", end="")
        for l in self.gcc_tools.get_elf_symbols(elf_file):
            self.parse_elf_symbols(l)
        print("total %d" % len(self.symbols.values()))

        print("unmangling c++ symbols")
        self.unmangle_cpp_names()

        print("parse symbols path line")
        for l in self.gcc_tools.get_elf_symbols_file_line(elf_file):
            self.parse_elf_symbols_file_line(l)

        print("parse assembly text")
        count = self.parse_assembly_text(
            "".join(self.gcc_tools.get_assembly_lines(elf_file)))

        print("parsed total %d functions" % count)
        print("parsed total %d variable" %
              (len(self.symbols.values()) - count))

        self.elf_mtime = os.path.getmtime(elf_file)

    # [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
    # [ 4] .text             PROGBITS        a0000c00 002c00 011cc0 00  AX  0   0 64
    # [ 5] .itcm_region      PROGBITS        62fc0000 015000 000d90 00  AX  0   0 16
    # [ 6] .dtcm_region      PROGBITS        62fc5000 016af8 000000 00   W  0   0  1
    parse_elf_section_pattern = re.compile(
        r"^\s+\[\s*(\d+)\]\s+([\.\w]+)\s+(\w+)\s+(\w+)\s\w+\s(\w+)\s\d+\s+([a-zA-Z]+)\s+(\d+\s+){2}(\d+)")

    def parse_elf_section(self, lines):
        match = self.parse_elf_section_pattern.match(lines)
        if not match:
            return False

        s_index = int(match.group(1))
        s_name = match.group(2)
        s_type = match.group(3)
        s_addr = int(match.group(4), 16)
        s_size = int(match.group(5), 16)
        s_flag = match.group(6)
        s_align = int(match.group(8))

        if s_addr > 0:
            sec = self.section.get(s_index, {})
            sec[NAME] = s_name
            sec[TYPE] = s_type
            sec[ADDRESS] = s_addr
            sec[SIZE] = s_size
            sec[FLAG] = s_flag
            sec[ALIGN] = s_align
            self.section[s_index] = sec
        else:
            return False

        return sec

    # 41: 00000000     0 FILE    LOCAL  DEFAULT  ABS vfprintf.c
    # 42: a0004d50   146 FUNC    LOCAL  DEFAULT    4 __sbprintf
    # 43: a0011e2c    16 OBJECT  LOCAL  DEFAULT    4 blanks.1
    parse_elf_symbols_pattern = re.compile(
        r"^\s+\d+:\s+([\da-f]{8})\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([\.\w]+)")

    def parse_elf_symbols(self, lines):
        match = self.parse_elf_symbols_pattern.match(lines)
        if not match:
            return False

        s_addr = match.group(1)
        s_size = int(match.group(2))
        s_type = match.group(3)
        s_bind = match.group(4)
        s_vis = match.group(5)
        s_sec = match.group(6)
        s_name = match.group(7)

        types = {"FUNC": TYPE_FUNCTION, "OBJECT": TYPE_VARIABLE}

        if (s_size > 0) and (s_type in ["FUNC", "OBJECT"]):
            return self.symbol_create(s_name, s_addr, types.get(s_type), s_size, int(s_sec), s_bind)
        else:
            return False

    def unmangle_cpp_names(self):
        s_name = list(symbol[NAME] for symbol in self.all_symbols())

        unmangled_names = self.gcc_tools.get_unmangled_names(s_name)

        for s in self.all_symbols():
            s[DISPLAY_NAME] = unmangled_names[s[NAME]]

    # 9ffff000 00000100 D fw_header	/home/egahp/bsp/board/bl616dk/fw_header.c:3
    # a0000000 0000004e T __start	/home/egahp/drivers/soc/bl616/std/startup/start.S:12
    # a000004e t __exit	/home/egahp/drivers/soc/bl616/std/startup/start.S:56
    parse_elf_symbols_file_line_pattern = re.compile(
        r"^([\da-f]{8})(\s+0[\da-f]{7})?\s+\w\s+([\.\w]+)\s+([^:]+):(\d+)")

    def parse_elf_symbols_file_line(self, line):
        match = self.parse_elf_symbols_file_line_pattern.match(line)
        if not match:
            return False

        s_addr = int(match.group(1), 16)
        s_name = match.group(3)
        s_file = match.group(4)
        s_line = int(match.group(5))

        self.symbol_add_file_line(s_addr, s_name, s_file, s_line)

        return True

    find_symbol_in_map_pattern = re.compile(
        r"^\w+\s+([-\.\/\w]+)\(([-\.\/\w]+)\)")

    def parse_map(self, map_file):

        map_file_obj = open(map_file, 'r')
        map_file_content = ""
        try:
            map_file_content = map_file_obj.read()
        finally:
            map_file_obj.close()

        map_file_content = map_file_content[map_file_content.find(
            "Cross Reference Table"):]

        for sym in self.all_functions():
            if PATH not in sym:
                s_name = sym[NAME]
                s_addr = int(sym[ADDRESS], 16)
                map_index = map_file_content.find('\n' + s_name) + 1
                match = self.find_symbol_in_map_pattern.match(
                    map_file_content[map_index:])
                if match:
                    file_path = '$without_debuginfo/' + \
                        match.group(1) + '/' + match.group(2)
                    self.symbol_add_file_line(s_addr, s_name, file_path, None)
                else:
                    file_path = "$unknown_generated/" + sym[BIND]
                    self.symbol_add_file_line(s_addr, s_name, file_path, None)

        for sym in self.all_variables():
            if PATH not in sym:
                s_name = sym[NAME]
                s_addr = int(sym[ADDRESS], 16)
                file_path = "$unknown_generated/" + sym[BIND]
                self.symbol_add_file_line(s_addr, s_name, file_path, None)

        for sym in self.all_functions():
            if PATH not in sym:
                print(sym[NAME])

    # 00000098 <pbl_table_addr>:
    # 00000098 <pbl_table_addr.constprop.0>:
    parse_assembly_text_function_start_pattern = re.compile(
        r"^([\da-f]{8})\s+<([\.\w]*)>:")

    def parse_assembly_text(self, assembly):
        name = None
        addr = None
        assembly_lines = []
        found_symbols = 0

        def flush_current_symbol():
            if name and addr:
                if False == self.symbol_add_assembly(int(addr, 16), assembly_lines):
                    return 0
                return 1
            return 0

        for line in assembly.split("\n"):
            match = self.parse_assembly_text_function_start_pattern.match(line)
            if match:
                found_symbols += flush_current_symbol()
                addr = match.group(1)
                name = match.group(2)
                assembly_lines = []
            else:
                if line.strip() != "":
                    assembly_lines.append(line)

        found_symbols += flush_current_symbol()
        return found_symbols

    def parse_su(self, su_dir):

        def gen_find(filepat, top):
            for path, dirlist, filelist in os.walk(top):
                for name in fnmatch.filter(filelist, filepat):
                    yield os.path.join(path, name)

        def gen_open(filenames):
            for name in filenames:
                yield open(name)

        def gen_cat(sources):
            for s in sources:
                for item in s:
                    yield item

        def get_stack_usage_lines(su_dir):
            names = gen_find("*.su", su_dir)
            files = gen_open(names)
            lines = gen_cat(files)
            return lines

        if su_dir:
            print("parsing stack usages starting at %s" % su_dir)
            print("find symbol missing paths from su file")

            missing_path_symbols = [
                s for s in self.all_functions() if s.get(PATH, None) == None]

            # find canfix path symbols
            for sym1 in missing_path_symbols:
                for sym2 in missing_path_symbols:
                    if (sym1[ADDRESS] != sym2[ADDRESS]):
                        if (sym1[NAME] == sym2[NAME]):
                            sym1[CANTFIX] = True
                            sym2[CANTFIX] = True

            canfix_path_symbols = [
                s for s in missing_path_symbols if s.get(CANTFIX, False) == False]

            for l in get_stack_usage_lines(su_dir):
                self.parse_stack_usage_line(l, canfix_path_symbols)

    # puncover_riscv.c:8:43:dynamic_stack2	16	dynamic
    # puncover_riscv.c:14:40:0	16	dynamic,bounded
    # puncover_riscv.c:8:43:dynamic_stack2	16	dynamic
    # /home/egahp/drivers/lhal/config/bl616/device_table.c:321:6:bflb_device_set_userdata	0	static
    parse_stack_usage_line_pattern = re.compile(
        r"^(.*?\.[ch]([ch]|pp)?):(\d+):(\d+):([^\t]+)\t+(\d+)\t+([a-z,]+)")

    def parse_stack_usage_line(self, line, canfix_symbols):
        match = self.parse_stack_usage_line_pattern.match(line)
        if not match:
            return False

        s_file = match.group(1)
        s_line = int(match.group(3))
        s_name = match.group(5)
        s_stack_size = int(match.group(6))
        s_qualifier = match.group(7)

        for sym in canfix_symbols:
            if sym[NAME] == s_name:
                self.symbol_add_file_line(
                    int(sym[ADDRESS], 16), sym[NAME], s_file, s_line)
                canfix_symbols.remove(sym)
                break

        return self.symbol_add_stack_usage(s_file, s_line, s_name, s_stack_size, s_qualifier)

    # TODO: handle operators, e.g. String::operator=(char const*)
    # TODO: handle templates, e.g. void LinkedList<T>::clear() [with T = Loggable]
    re_cpp_display_name = re.compile(
        r"^(\w[^\(\s]*\s)*(\w+::~?)?(\w+)(\([^\)]*\))?(\sconst)?$")

    def display_name_simplified(self, name):
        # .su files have elements such as "virtual size_t Print::write(const uint8_t*, size_t)"
        # c++filt gives us "Print::write(unsigned char const*, unsigned int)"

        m = self.re_cpp_display_name.match(name)
        if m:
            groups = list(m.groups(''))

            def replace_identifiers(m):
                # these values were derived from an ARM 32Bit target
                # it could be that they need further adjustments
                # yes, we are treating int as long works only for 32bit platforms
                # right now, our sample projects use both types unpredictably in the same binary (oh, dear)
                mapping = {
                    'const': '',  # we ignore those as a feasible simplification
                    'size_t': 'unsigned long',
                    'uint8_t': 'unsigned char',
                    'int8_t': 'signed char',
                    'uint16_t': 'unsigned short',
                    'int16_t': 'short',
                    'uint32_t': 'unsigned long',
                    'int32_t': 'long',
                    'uint64_t': 'unsigned long long',
                    'int64_t': 'long long',
                    'byte': 'unsigned char',
                    'int': 'long',
                }

                return mapping.get(m.group(), m.group())

            # in case, we have parameters, simplify those
            groups[3] = re.sub(r'\w+', replace_identifiers, groups[3])

            # TODO: C allows you to write the same C types in many different notations
            # http://ieng9.ucsd.edu/~cs30x/Std.C/types.html#Basic%20Integer%20Types
            # applies to tNMEA2000::SetProductInformation or Print::printNumber

            # remove leading "virtual size_t" etc.
            # non-matching groups should be empty strings
            name = ''.join(groups[1:])

        # remove white space artifacts from previous replacements
        for k, v in [('   ', ' '), ('  ', ' '), ('( ', '('), (' )', ')'), ('< ', '<'), (' >', '>'), (' *', '*'), (' &', '&')]:
            name = name.replace(k, v)

        return name

    def display_names_match(self, a, b):
        if a is None or b is None:
            return False

        if a == b:
            return True

        simplified_a = self.display_name_simplified(a)
        simplified_b = self.display_name_simplified(b)
        return simplified_a == simplified_b

    def normalize_files_paths(self, base_dir):
        base_dir = os.path.abspath(base_dir) if base_dir else "/"

        for s in self.all_symbols():
            path = s.get(PATH, None)
            if path:
                if path.startswith(base_dir):
                    path = os.path.relpath(path, base_dir)
                elif path.startswith("/"):
                    path = path[1:]
                s[PATH] = path

    def sorted_by_size(self, symbols):
        return sorted(symbols, key=lambda k: k.get("size", 0), reverse=True)

    def all_symbols(self):
        return self.sorted_by_size(self.symbols.values())

    def all_functions(self):
        return list([f for f in self.all_symbols() if f.get(TYPE, None) == TYPE_FUNCTION])

    def all_variables(self):
        return list([f for f in self.all_symbols() if f.get(TYPE, None) == TYPE_VARIABLE])

    def enhance(self, src_root):
        print("enhancing libc symbols")
        self.enhance_libc_symbols()

        self.normalize_files_paths(src_root)
        print("enhancing function sizes")
        self.enhance_function_size_from_assembly()
        print("deriving folders")
        self.derive_folders()
        print("enhancing file elements")
        self.enhance_file_elements()
        print("enhancing assembly")
        self.enhance_assembly()
        print("enhancing call tree")
        self.enhance_call_tree()
        print("enhancing siblings")
        self.enhance_sibling_symbols()
        self.enhance_symbol_flags()

    is_libc_softfp_pattern = re.compile(
        r".*\/source\/riscv\/riscv-gcc\/libgcc\/soft-fp\/(.+)")

    is_libc_pattern = re.compile(
        r".*(\/source\/riscv\/riscv-gcc\/libgcc\/|\/riscv64-unknown-elf\/(include|lib)\/)(.+)")

    heap_functions = ["malloc", "realloc", "calloc", "memalign", "_sbrk_r", "_malloc_r",
                      "_realloc_r", "_calloc_r", "_memalign_r", "_free_r",
                      "free", "kmalloc", "kfree", "pvPortMallocStack", "vPortFreeStack"]

    def enhance_libc_symbols(self):
        for sym in self.symbols.values():
            match = self.is_libc_softfp_pattern.match(sym[PATH])

            if match:
                sym[PATH] = "/$libc/libgcc/soft-fp/" + match.group(1)
                sym["is_libc_softfp"] = True
                sym["is_libc"] = True
            else:
                match = self.is_libc_pattern.match(sym[PATH])

                if match:
                    if match.group(1) == "/riscv64-unknown-elf/include/":
                        sym[PATH] = "/$libc/include/" + match.group(3)
                    elif match.group(1) == "/source/riscv/riscv-gcc/libgcc/":
                        sym[PATH] = "/$libc/libgcc/" + match.group(3)
                    else:
                        sym[PATH] = "/$libc/" + match.group(3)
                    sym["is_libc"] = True

            for heap in self.heap_functions:
                if sym[NAME] == heap:
                    sym["is_heap"] = True

        return True

    def derive_folders(self):
        for s in self.all_symbols():
            p = s.get(PATH, "$unknown/unknown")
            p = os.path.normpath(p)
            s[PATH] = p
            s[BASE_FILE] = os.path.basename(p)
            s[FILE] = self.file_for_path(p)
            s[FILE][SYMBOLS].append(s)

    def enhance_assembly(self):
        for key, symbol in self.symbols.items():
            if ASM in symbol:
                symbol[ASM] = list([self.enhanced_assembly_line(l)
                                   for l in symbol[ASM]])

    #   98: a8a8a8a8  bl 98
    # a0004074:	35a1                	jal	a0003ebc
    enhanced_assembly_line_pattern = re.compile(
        r"^\s*[\da-f]+:\s+[\d\sa-f]{9}\s+(jal|bl)\s+([\d\sa-f]+)\s*$")

    def enhanced_assembly_line(self, line):
        match = self.enhanced_assembly_line_pattern.match(line)
        if match:
            symbol = self.symbol_by_addr(match.group(2))
            if symbol:
                return line + " <%s>" % (symbol["name"])
        return line

    def enhance_call_tree(self):
        for f in self.all_functions():
            for k in [CALLERS, CALLEES]:
                f[k] = f.get(k, [])

        for f in self.all_functions():
            if ASM in f:
                [self.enhance_call_tree_from_assembly_line(
                    f, l) for l in f[ASM]]

    # 寄存器跳转无法追踪
    # a0002c3e:	8682                	jr	a3
    # a0003f04:	9982                	jalr	s3
    # a0005902:	c54080e7          	jalr	-940(ra) # 62fc0552 <bflb_irq_save>
    # a00066a6:	a3e30067          	jr	-1474(t1) # 62fc00e0 <bflb_ef_ctrl_read_direct>
    # 立即数跳转
    # a0003e7c:	bf55                	j	a0003e30 <main+0x38>
    # a000617c:	d85ff06f          	j	a0005f00 <default_interrupt_handler>
    # a0005e54:	3d19                	jal	a0005c6a <rvpmp_fill_entry>
    # a0003078:	00091363          	bnez	s2,a000307e <__muldf3+0x56c>
    # a000304e:	c8070de3          	beqz	a4,a0002ce8 <__muldf3+0x1d6>
    # a0003bd8:	0005da63          	bgez	a1,a0003bec <__floatdidf+0x40>
    # a0003d20:	000bc863          	bltz	s7,a0003d30 <__floatdidf+0x184>
    # a000311e:	12c05163          	blez	a2,a0003240 <__subdf3+0x190>
    # a0003d6e:	00f04963          	bgtz	a5,a0003d80 <__lshrdi3+0x1c>
    # a0002e74:	cb25                	beqz	a4,a0002ee4 <__muldf3+0x3d2>
    # a0003094:	f5ed                	bnez	a1,a000307e <__muldf3+0x56c>
    # a000632a:	b07ff0ef          	jal	ra,a0005e30 <rvpmp_init>
    # a0006288:	fed71ae3          	bne	a4,a3,a000627c <start_load+0xbc>
    # a0005e4a:	02890063          	beq	s2,s0,a0005e6a <rvpmp_init+0x3a>
    # a0002a10:	0105da63          	bge	a1,a6,a0002a24 <__gedf2+0x7e>
    # a0001a98:	06a64063          	blt	a2,a0,a0001af8 <__adddf3+0x13a>
    # a0002d50:	01e87363          	bgeu	a6,t5,a0002d56 <__muldf3+0x244>
    # a0002390:	0ad56a63          	bltu	a0,a3,a0002444 <__divdf3+0x1ce>
    # 直接读取#号后面的地址
    # a00058fe:	c2fbb097          	auipc	ra,0xc2fbb
    # a0005902:	c54080e7          	jalr	-940(ra) # 62fc0552 <bflb_irq_save>
    # 尾调用无需再次保存ra
    # a00066a2:	c2fba317          	auipc	t1,0xc2fba
    # a00066a6:	a3e30067          	jr	-1474(t1) # 62fc00e0 <bflb_ef_ctrl_read_direct>

    enhance_call_tree_pattern = re.compile(
        r"^\s*[\da-f]{8}:\s+([\da-f]{4}|[\da-f]{8})\s+((JR|JALR)\s+.*#\s+|(J|JAL|BNEZ|BEQZ|BGEZ|BLTZ|BLEZ|BGTZ|BEQZ|BNEZ|BNE|BEQ|BGE|BLT|BGEU|BLTU)\s*([a-z\d]{2},){0,2})([\da-f]{8})", re.IGNORECASE)

    enhance_call_rv_isa_fd = re.compile(
        r"^\s*[\da-f]{8}:\s+([\da-f]{4}|[\da-f]{8})\s+(fm|fcvt|fl|fs|fadd|fdiv|fnm|feq|fclass|fr)", re.IGNORECASE)

    def enhance_call_tree_from_assembly_line(self, function, line):
        if "f" in line:
            match = self.enhance_call_rv_isa_fd.match(line)

            if match:
                function["call_hard_float"] = True

        if "<" not in line:
            return False

        match = self.enhance_call_tree_pattern.match(line)

        if match:
            callee = self.symbol_by_addr(match.group(6))
            if callee:
                self.symbol_add_function_call(function, callee)
                return True

        return False

    # a0000008:	30047073          	csrci	mstatus,8
    # a0000c00:	8eaa                	mv	t4,a0
    # 88a:	ebad 0d03 	sub.w	sp, sp, r3
    count_assembly_code_bytes_re = re.compile(
        r"^\s*[\da-f]+:\s+([\d\sa-f]{9})")

    def count_assembly_code_bytes(self, line):
        match = self.count_assembly_code_bytes_re.match(line)
        if match:
            return len(match.group(1).replace(" ", "")) // 2
        return 0

    def enhance_function_size_from_assembly(self):
        for f in self.all_symbols():
            if ASM in f:
                f[SIZE] = sum([self.count_assembly_code_bytes(l)
                              for l in f[ASM]])

    def enhance_sibling_symbols(self):
        for f in self.all_functions():
            if SIZE in f:
                addr = int(f.get(ADDRESS), 16) + f.get(SIZE)
                next_symbol = self.symbol_by_addr(hex(addr))
                if next_symbol and next_symbol.get(TYPE, None) == TYPE_FUNCTION:
                    f[NEXT_FUNCTION] = next_symbol

        for f in self.all_functions():
            n = f.get(NEXT_FUNCTION, None)
            if n:
                n[PREV_FUNCTION] = f

    def file_element_for_path(self, path, type, default_values):
        if not path:
            return None

        result = self.file_elements.get(path, None)
        if not result:
            parent_dir = os.path.dirname(path)
            parent_folder = self.folder_for_path(
                parent_dir) if parent_dir and parent_dir != "/" else None
            result = {
                TYPE: type,
                PATH: path,
                FOLDER: parent_folder,
                NAME: os.path.basename(path),
            }
            for k, v in default_values.items():
                result[k] = v
            self.file_elements[path] = result

        return result if result[TYPE] == type else None

    def file_for_path(self, path):
        return self.file_element_for_path(path, TYPE_FILE, {SYMBOLS: []})

    def folder_for_path(self, path):
        return self.file_element_for_path(path, TYPE_FOLDER, {FILES: [], SUB_FOLDERS: [], COLLAPSED_SUB_FOLDERS: []})

    def file_items_ancestors(self, item):
        while item.get(FOLDER):
            item = item[FOLDER]
            yield item

    def enhance_file_elements(self):
        for f in self.all_files():
            parent = f.get(FOLDER, None)
            if parent:
                parent[FILES].append(f)

            f[SYMBOLS] = sorted(f[SYMBOLS], key=lambda s: s[NAME])
            f[FUNCTIONS] = list(
                [s for s in f[SYMBOLS] if s.get(TYPE, None) == TYPE_FUNCTION])
            f[VARIABLES] = list(
                [s for s in f[SYMBOLS] if s.get(TYPE, None) == TYPE_VARIABLE])

        for f in self.all_folders():
            parent = f.get(FOLDER, None)
            if parent:
                parent[SUB_FOLDERS].append(f)
            ancestors = list(self.file_items_ancestors(f))
            f[ANCESTORS] = ancestors
            if len(ancestors) > 0:
                f[ROOT] = ancestors[-1]

            collapsed_name = f[NAME]
            for a in ancestors:
                if len(f[FILES]) > 0:
                    a[COLLAPSED_SUB_FOLDERS].append(f)
                if len(a[FILES]) > 0:
                    break
                collapsed_name = os.path.join(a[NAME], collapsed_name)
            f[COLLAPSED_NAME] = collapsed_name

        for f in self.all_folders():
            for k in [FILES, SUB_FOLDERS]:
                f[k] = sorted(f[k], key=lambda s: s[NAME])
            f[COLLAPSED_SUB_FOLDERS] = sorted(
                f[COLLAPSED_SUB_FOLDERS], key=lambda s: s[COLLAPSED_NAME])

    def all_files(self):
        return [f for f in self.file_elements.values() if f[TYPE] == TYPE_FILE]

    def all_folders(self):
        return [f for f in self.file_elements.values() if f[TYPE] == TYPE_FOLDER]

    def root_folders(self):
        return [f for f in self.all_folders() if not f[FOLDER]]

    def collapsed_root_folders(self):
        result = []

        def non_empty_leafs(f):
            if len(f[FILES]) > 0:
                result.append(f)
            else:
                for s in f[SUB_FOLDERS]:
                    non_empty_leafs(s)

        for f in self.root_folders():
            non_empty_leafs(f)

        return result

    def enhance_symbol_flags(self):
        # is_float_function_pattern = re.compile(
        #     r"^__((add|sub|mul|div|neg|extend|trunc|fix|fixun|float|floatun|cmp|unord|eq|ne|ge|lt|le|gt|pow)((sf2|sf3|df2|df3|tf2|tf3|xf2|xf3|sc3|dc3|tc3|xc3)|(sf|df|tf|xf)(si|di|ti|sf2|df2|tf2|xf2)|(si|di|ti|)(sf|df|tf|xf)))$")

        # def is_float_function_name(n):
        #     return is_float_function_pattern.match(n)

        # soft_float_func = [
        #     f for f in self.all_functions() if is_float_function_name(f[NAME])]

        soft_float_func = [
            f for f in self.all_functions() if f.get("is_libc_softfp", False)]
        heap_func = [f for f in self.all_functions()
                     if f.get("is_heap", False)]

        for f in self.all_functions():
            callees = f[CALLEES]
            f["call_soft_float"] = any(
                [ff in callees for ff in soft_float_func])
            f["call_hard_float"] = f.get("call_hard_float", False)
            f["call_heap"] = any(
                [ff in callees for ff in heap_func])

        for file in self.all_files():
            file["call_soft_float"] = any(
                [f["call_soft_float"] for f in file[FUNCTIONS]])
            file["call_hard_float"] = any(
                [f["call_hard_float"] for f in file[FUNCTIONS]])
            file["call_heap"] = any(
                [f["call_heap"] for f in file[FUNCTIONS]])

        def folder_calls_some(folder):
            result_call_soft_float = any(
                [f["call_soft_float"] for f in folder[FILES]])
            result_call_hard_float = any(
                [f["call_hard_float"] for f in folder[FILES]])
            result_call_heap = any([f["call_heap"] for f in folder[FILES]])

            for sub_folder in folder[SUB_FOLDERS]:
                ret = folder_calls_some(sub_folder)

                if ret[0]:
                    result_call_soft_float = True
                if ret[1]:
                    result_call_hard_float = True
                if ret[2]:
                    result_call_heap = True

            folder["call_soft_float"] = result_call_soft_float
            folder["call_hard_float"] = result_call_hard_float
            folder["call_heap"] = result_call_heap

            return [result_call_soft_float, result_call_hard_float, result_call_heap]

        for folder in self.root_folders():
            folder_calls_some(folder)

    def build_symbol_name_index(self):
        if not self.symbols_by_name or not self.symbols_by_qualified_name:
            self.symbols_by_name = {}
            self.symbols_by_qualified_name = {}

            for s in self.symbols.values():
                name = s[NAME]
                if name:
                    self.symbols_by_name[name] = s

                qualified_name = self.qualified_symbol_name(s)
                if qualified_name:
                    self.symbols_by_qualified_name[qualified_name] = s
