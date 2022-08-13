from idc import BADADDR
import ida_idaapi
import ida_kernwin
import ida_enum
import ida_hexrays
import ida_lines
import ida_typeinf
import ida_name
import ida_struct


class switch_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.current_switch_number = -1
        self.wanted_switch_number = -1
        self.current_function = BADADDR

    def visit_insn(self, cinsn: ida_hexrays.cinsn_t):
        if cinsn.op == ida_hexrays.cit_switch:
            self.current_switch_number += 1
            if self.wanted_switch_number != self.current_switch_number:
                return 0

            expr = cinsn.cswitch.expr
            if expr.op == ida_hexrays.cot_cast:
                expr = expr.x
            if expr.op == ida_hexrays.cot_call and \
               expr.x.op == ida_hexrays.cot_obj:
                cfunc = ida_hexrays.decompile(expr.x.obj_ea)
                ptif = ida_typeinf.tinfo_t()
                ptif.create_ptr(cfunc.type)

                # find out how long is the text of the return type
                # it is a bit complicated because it deals with the following
                # unsigned types, pointers, functions pointers and call types
                func_prototype = ptif.dstr()
                ret_type_len = len(func_prototype)
                bracket_counter = 0
                closed_counter = 0
                new_bracket = False
                for char in reversed(func_prototype):
                    ret_type_len -= 1
                    if char == ')':
                        bracket_counter += 1
                        new_bracket = True
                    if char == '(':
                        bracket_counter -= 1

                    if bracket_counter == 0 and new_bracket:
                        closed_counter += 1
                        new_bracket = False

                    if closed_counter == 2:
                        break

                enum_name = func_prototype[:ret_type_len].strip()
                enum = ida_enum.get_enum(enum_name)
                if enum == BADADDR:
                    func_name = ida_name.get_short_name(expr.x.obj_ea)
                    enum_name = f"{func_name[:func_name.find('(')]}_return_code"
                    enum = ida_enum.get_enum(enum_name)
                    if enum == BADADDR:
                        enum = ida_enum.add_enum(BADADDR, enum_name, 0)
                        if enum == BADADDR:
                            return 0

                    new_prototype = f"{enum_name}{func_prototype[ret_type_len:]};"
                    ida_typeinf.apply_cdecl(None, expr.x.obj_ea, new_prototype)

            elif expr.op == ida_hexrays.cot_memptr or \
                    expr.op == ida_hexrays.cot_memref:
                offset = expr.m
                expr_type = expr.x.type
                expr_type.remove_ptr_or_array()
                sid = ida_struct.get_struc_id(expr_type.dstr())
                struct = ida_struct.get_struc(sid)
                member = ida_struct.get_member(struct, offset)
                member_tinfo = ida_typeinf.tinfo_t()
                ida_struct.get_member_tinfo(member_tinfo, member)
                if member_tinfo.is_enum():
                    enum_name = member_tinfo.get_type_name()
                    enum = ida_enum.get_enum(enum_name)
                else:
                    mid = ida_struct.get_member_id(struct, offset)
                    enum_name = f"{ida_struct.get_member_name(mid)}_code"
                    enum = ida_enum.get_enum(enum_name)
                    if enum == BADADDR:
                        enum = ida_enum.add_enum(BADADDR, enum_name, 0)
                        if enum == BADADDR:
                            return 0
                    enum_tinfo = ida_typeinf.tinfo_t()
                    ida_typeinf.parse_decl(enum_tinfo, None, enum_name+";", 0)
                    ida_struct.set_member_tinfo(struct, member, 0, enum_tinfo, 0)

            elif expr.op == ida_hexrays.cot_var:
                var_ref = expr.v.getv()
                var_type = var_ref.type()
                if var_type.is_enum():
                    enum_name = var_type.get_type_name()
                    enum = ida_enum.get_enum(enum_name)
                else:
                    # Don't try to get the enum with the name of the variable
                    # because variable names are often duplicate
                    enum_name = f"{var_ref.name}_code"
                    enum = ida_enum.add_enum(BADADDR, enum_name, 0)
                    enum_tinfo = ida_typeinf.tinfo_t()
                    ida_typeinf.parse_decl(enum_tinfo, None, enum_name+";", 0)
                    lsi = ida_hexrays.lvar_saved_info_t()
                    lsi.ll = var_ref
                    lsi.type = enum_tinfo
                    ida_hexrays.modify_user_lvar_info(self.current_function, ida_hexrays.MLI_TYPE, lsi)
            else:
                return 0

            for case in cinsn.cswitch.cases:
                for num in case.values:
                    ida_enum.add_enum_member(enum, f"case_{num}_{enum_name}", num)
        return 0


class ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        self.visitor = switch_visitor()

    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        wanted_switch = -1
        cfunc = ida_hexrays.decompile(ctx.cur_func)
        place, _, _ = ida_kernwin.get_custom_viewer_place(ctx.widget, False)
        selected_line_num = ida_kernwin.place_t.as_simpleline_place_t(place).n
        current_line_num = -1
        for line in cfunc.pseudocode:
            current_line_num += 1
            current_line = ida_lines.tag_remove(line.line)
            if current_line.lstrip().startswith("switch "):
                wanted_switch += 1
            if current_line_num > selected_line_num:
                break

        self.visitor.current_switch_number = -1
        self.visitor.wanted_switch_number = wanted_switch

        if cfunc:
            self.visitor.current_function = ctx.cur_func.start_ea
            self.visitor.apply_to(cfunc.body, None)

    def update(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        curline = ida_lines.tag_remove(ida_kernwin.get_custom_viewer_curline(ctx.widget, False))
        if curline.lstrip().startswith("switch "):
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE


class EnumHim(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "EnumHim"
    help = "Generate an enum from switch case"

    def init(self):
        print("EnumHim initialized")
        act = ida_kernwin.action_desc_t(
            "EnumHim",
            "EnumHim",
            ActionHandler(),
            "SHIFT+M"
        )
        ida_kernwin.register_action(act)

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return EnumHim()
