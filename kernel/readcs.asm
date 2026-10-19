PUBLIC vmd_read_cs
PUBLIC vmd_read_msr
PUBLIC vmd_read_port
PUBLIC vmd_write_selector
.code
vmd_read_cs PROC
    mov ax, cs
    ret
vmd_read_cs ENDP
vmd_read_msr PROC
    rdmsr
    shl rdx, 32
    or rax, rdx
    ret
vmd_read_msr ENDP
vmd_read_port PROC
    mov dx, cx
    in al, dx
    movzx eax, al
    ret
vmd_read_port ENDP
vmd_write_selector PROC
    mov ax, cx
    mov dx, 510h
    out dx, ax
    ret
vmd_write_selector ENDP
END
