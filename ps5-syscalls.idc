static add_sysent_struct(_num_syscalls, _sysents_start)
{
    auto typedef_id = add_struc(-1, "sy_call_t", 0);

    auto struct_id = add_struc(-1, "sysent", 0);
    add_struc_member(struct_id, "n_arg", 0x00, FF_DWORD, -1, 4);
    add_struc_member(struct_id, "pad_0x04", 0x04, FF_DWORD, -1, 4);
    add_struc_member(struct_id, "sy_call", 0x08, FF_QWORD | FF_0OFF, -1, 8);
    add_struc_member(struct_id, "sy_auevent", 0x10, FF_QWORD, -1, 8);
    add_struc_member(struct_id, "sy_systrace_args", 0x18, FF_QWORD, -1, 8);
    add_struc_member(struct_id, "sy_entry", 0x20, FF_DWORD, -1, 4);
    add_struc_member(struct_id, "sy_return", 0x24, FF_DWORD, -1, 4);
    add_struc_member(struct_id, "sy_flags", 0x28, FF_DWORD, -1, 4);
    add_struc_member(struct_id, "sy_thrcnt", 0x2C, FF_DWORD, -1, 4);
    
    del_items(_sysents_start, DELIT_SIMPLE, _num_syscalls * 0x30);
    create_struct(_sysents_start, 0x30, "sysent");
    make_array(_sysents_start, _num_syscalls);
    set_array_params(_sysents_start, AP_INDEX, 1, -1);
}

static sanitize_string(s)
{
    auto out = "";
    auto i = 0;
    for (i = 0; i < strlen(s); i++)
    {
        auto c = s[i];
        if (c == "#" || c == "{")
        {
             c = "";
        }
        if (c == ".")
        {
            c = "_";
        }
        
        out = sprintf("%s%s", out, c);
    }
    
    return out;
}

static resolve_name(_str_start, _saved_sys_nosys, _sys_index, _sys_call)
{
    if (_sys_call == _saved_sys_nosys)
    {
        return "sys_nosys";
    }

    auto sys_name_addr = Qword(_str_start + (8 * _sys_index));
    auto sys_name = get_strlit_contents(sys_name_addr, -1, STRTYPE_C);
    return sprintf("sys_%s", sanitize_string(sys_name));
}

static main()
{
    // this might need to be adjusted in the future
    auto num_syscalls = 722;

    auto sysents_start = FindBinary(0, SEARCH_DOWN, "00 00 00 00 00 00 00 00 ? ? ? ? FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 ? ? ? ? FF FF FF FF 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00");
    Message("sysents_start: %X\n\n", sysents_start);
    
    add_sysent_struct(num_syscalls, sysents_start);
    MakeName(sysents_start, "sysents");
    
    auto sysents_current = sysents_start;
    auto sysents_end = sysents_start + (0x30 * num_syscalls);
    
    auto search_str = FindBinary(0, SEARCH_DOWN, "63 6F 6D 70 61 74 2E 63 72 65 61 74 00");
    auto b0 = (search_str >> 0) & 0xFF;
    auto b1 = (search_str >> 8) & 0xFF;
    auto b2 = (search_str >> 16) & 0xFF;
    auto b3 = (search_str >> 24) & 0xFF;
    auto search_str_ptr = FindBinary(0, SEARCH_DOWN, sprintf("%02X %02X %02X %02X FF FF FF FF", b0, b1, b2, b3));
    
    // save global var so we can resolve strings by index
    auto global_str_start = search_str_ptr - 0x40;
    
    auto str_start = global_str_start;
    auto str_end = str_start + (num_syscalls * 8);
    while (str_start < str_end)
    {
        MakeQword(str_start);
        MakeStr(Qword(str_start), 0);
        str_start = str_start + 8;
    }
    
    auto saved_sys_nosys = 0;
    auto sys_idx = 0;
    while (sysents_current < sysents_end)
    {
        auto sys_call_ptr = Qword(sysents_current + 0x08);
        if (sys_idx == 0)
        {
            saved_sys_nosys = sys_call_ptr;
        }
        
        auto resolved_name = resolve_name(global_str_start, saved_sys_nosys, sys_idx, sys_call_ptr);
        Message("%03i - 0x%X   %s\n", sys_idx, sys_call_ptr, resolved_name);
        
        // make the actual function
        auto target = Dword(sys_call_ptr + 1);
        auto final_target = target + sys_call_ptr + 5;
        del_items(final_target, DELIT_SIMPLE, 1);
        MakeCode(final_target);
        MakeName(final_target, sprintf("%s", resolved_name));
        MakeFunction(final_target, 0);
        
        // make the jump function prefixed with _
        del_items(sys_call_ptr, DELIT_SIMPLE, 5);
        MakeCode(sys_call_ptr);
        MakeFunction(sys_call_ptr, sys_call_ptr + 5);
        
        sys_idx++;
        sysents_current = sysents_current + 0x30;
    }
}
