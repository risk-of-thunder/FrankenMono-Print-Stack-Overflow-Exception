extern lpRemain:QWORD

.code 
hkGetValue proc
	and         dword ptr [rbp],ebx
	sub rsp, 8
	jmp lpRemain
hkGetValue endp
end