;
;  Copyright © 2016 Odzhan, Peter Ferrie. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; -----------------------------------------------
; Rabbit stream cipher in x86 assembly
;
; size: 502 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------


    bits 32
    
    %ifndef BIN
      global RABBIT_setivx
      global _RABBIT_setivx
      
      global RABBIT_setkeyx
      global _RABBIT_setkeyx
      
      global RABBIT_cryptx
      global _RABBIT_cryptx
    %endif
    
; Calculate the next internal state
RABBIT_next_state:
_RABBIT_next_state:
    pushad                   ; save registers
    mov    esi, [esp+32+4]   ; esi = state
    pushad                   ; alloc 32-bytes for x-values
    mov    edi, esp
    mov    dword[edi+0*4], 0x4D34D34D
    mov    dword[edi+1*4], 0xD34D34D3
    mov    dword[edi+2*4], 0x34D34D34
    ; Calculate new counter values
    xor    ecx, ecx             ; i = 0 
rs_l0:
    mov    eax, ecx
    cdq
    push   3
    pop    ebx                  ;
    div    ebx
    mov    ebx, [edi+edx*4]     ; ebx = x[i % 3]
    add    ebx, [esi+64]        ; ebx += s->carry
    add    [esi+ecx*4+32], ebx  ; s->c[i] += ebx
    setc   [esi+64]             ; s->carry
    inc    ecx
    cmp    cl, 8
    jnz    rs_l0
    
    ; Calculate the g-values
    pushad
rs_l1:
    lodsd                       ; eax = s->x[i]
    add    eax, [esi+28]        ; eax += s->c[i]
    xor    edx, edx             ; edx = 0
    mul    eax                  ; edx:eax = eax * eax
    xor    eax, edx             ;
    stosd
    loop   rs_l1
    popad
    
    ; Calculate new state values
    dec    ecx                 ; j = 7
    cdq                        ; i = 0
    xchg   esi, edi
rs_l2:
    mov    eax, [esi+ecx*4-4]  ; eax = g[j-1]
    mov    ebx, [esi+ecx*4]    ; ebx = g[j]
    rol    eax, 16             ; 
    rol    ebx, 16             ; 
    add    eax, ebx            ; eax += ROTL32(g[j], 16)
    add    eax, [esi+edx*4]    ; eax += g[i]
    stosd
    inc    ecx
    inc    edx
    ; ----------------------
    mov    eax, ecx
    and    eax, 7
    mov    eax, [esi+eax*4]    ; eax = g[j & 7]
    rol    eax, 8
    add    eax, [esi+ecx*4-4]  ; eax += g[j-1]
    add    eax, [esi+edx*4]
    stosd
    inc    ecx
    inc    edx
    ; ----------------------
    and    ecx, 7              ; j &= 7
    cmp    dl, 8
    jnz    rs_l2
    
    popad                      ; release stack memory
    popad                      ; restore registers
    ret

; Key setup
RABBIT_setkeyx:
_RABBIT_setkeyx:
    pushad
    mov    edi, [esp+32+4]
    mov    esi, [esp+32+8]
    ; ---------------------
    ; Generate four subkeys
    ; ---------------------
    lodsd
    xchg   eax, edx
    lodsd
    xchg   eax, ebx
    lodsd
    xchg   eax, ecx
    lodsd
    xchg   eax, edx
    ; --------------------------------
    ; Generate initial state variables
    ; --------------------------------
    mov    [edi+4*0], eax
    mov    [edi+4*2], ebx
    mov    [edi+4*4], ecx
    mov    [edi+4*6], edx
    
    rol    eax, 16
    rol    ebx, 16
    rol    ecx, 16
    rol    edx, 16
    
    ; c->m.x[1] = U32V(k3<<16) | (k2>>16);
    mov    ebp, edx
    mov    bp, cx
    mov    [edi+4*1], ebp
    ; c->m.x[3] = U32V(k0<<16) | (k3>>16);
    mov    ebp, eax
    mov    bp, dx
    mov    [edi+4*3], ebp
    ; c->m.x[5] = U32V(k1<<16) | (k0>>16);
    mov    ebp, ebx
    mov    bp, ax
    mov    [edi+4*5], ebp
    ; c->m.x[7] = U32V(k2<<16) | (k1>>16);
    mov    ebp, ecx
    mov    bp, bx
    mov    [edi+4*7], ebp
    ; -------------------------------
    ; Generate initial counter values
    ; -------------------------------
    mov    [edi+4*0+32], ecx
    mov    [edi+4*2+32], edx
    mov    [edi+4*4+32], eax
    mov    [edi+4*6+32], ebx
    
    rol    eax, 16
    rol    ebx, 16
    rol    ecx, 16
    rol    edx, 16
    
    ; c->m.c[1] = (k0&0xFFFF0000) | (k1&0xFFFF);
    mov    ebp, eax
    mov    ax, bx           ; k1.lo
    mov    [edi+4*1+32], eax
    ; c->m.c[3] = (k1&0xFFFF0000) | (k2&0xFFFF);
    mov    bx, cx           ; k2.lo
    mov    [edi+4*3+32], ebx   
    ; c->m.c[5] = (k2&0xFFFF0000) | (k3&0xFFFF);
    mov    cx, dx           ; k3.lo
    mov    [edi+4*5+32], ecx    
    ; c->m.c[7] = (k3&0xFFFF0000) | (k0&0xFFFF);
    mov    dx, bp           ; k0.lo
    mov    [edi+4*7+32], edx
    
    xor    ecx, ecx
    and    dword[edi+64], ecx
    ; -----------------------------
    ; Iterate the system four times
    ; -----------------------------
    mov    cl, 4
rsk_l0:
    push   edi
    call   RABBIT_next_state
    pop    edi
    loop   rsk_l0
    
    ; -------------------
    ; Modify the counters
    ; -------------------
    xchg   eax, ecx
    cdq
rsk_l1:
    ; c->m.c[i] ^= c->m.x[(i+4) & 7];
    lea    ecx, [eax+edx+4]
    and    ecx, 7
    mov    ebx, [edi+ecx*4]
    xor    [edi+eax*4+32], ebx
    inc    eax
    cmp    al, 8
    jne    rsk_l1
    
    ; -------------------------------------
    ; Copy master instance to work instance
    ; -------------------------------------
    mov    cl, 68
    mov    esi, edi
    add    edi, ecx
    rep    movsb
    popad
    ret
    
    
; IV setup
RABBIT_setivx:
_RABBIT_setivx:
    ; save registers
    pushad
    mov    edx, [esp+32+4]   ; ctx
    mov    esi, [esp+32+8]   ; iv
    pushad                   ; create sv variable (32 bytes)
    ; Generate four subvectors
    lodsd
    mov    [esp], eax        ; sv[0] = v->d[0];
    xchg   eax, ebx
    lodsd
    mov    [esp+8], eax      ; sv[2] = v->d[1];
    
    ror    ebx, 16           ; sv[0] >> 16
    
    mov    ecx, eax          ; sv[1] = (sv[0]>>16) | (sv[2]&0xFFFF0000);
    mov    cx, bx
    mov    [esp+4], ecx
    
    mov    bx, ax            ; sv[3] = (sv[2]<<16) | (sv[0]&0x0000FFFF);
    ror    ebx, 16
    mov    [esp+12], ebx
    ; Modify counter values
    xor    ecx, ecx
rsv_l0:
    mov    eax, [edx+ecx*4+32]   ; eax = c->m.c[i]
    mov    ebx, ecx
    and    ebx, 3
    xor    eax, [esp+ebx*4]      ; eax ^= sv[i & 3]
    mov    [edx+ecx*4+100], eax  ; c->w.c[i] = eax
    inc    ecx
    cmp    cl, 8
    jnz    rsv_l0
    ; Copy master state variables to work
    pushad
    mov    esi, edx
    lea    edi, [esi+68]
    rep    movsd
    popad
    ; Iterate the system four times
    mov    cl, 4
rsv_l1:
    lea    eax, [edx+68]
    push   eax
    call   RABBIT_next_state ; RABBIT_next_state(&c->w);
    pop    eax
    loop   rsv_l1
    
    ; release sv of 32 bytes
    popad
    ; restore registers
    popad
    ret
    
; encrypt/decrypt a message of any size
RABBIT_cryptx:
_RABBIT_cryptx:
    pushad                   ; save registers
    lea    esi, [esp+32+4]   ; esi = parameters
    pushad                   ; alloc 32-bytes on stack
    lodsd
    xchg   ebx, eax          ; ebx=c
    lodsd
    xchg   ecx, eax          ; ecx=input
    lodsd
    xchg   ecx, eax          ; ecx=inlen
    xchg   eax, esi          ; esi=input
    add    ebx, 68           ; ebx=&c->w.x[0]
rc_l0:
    jecxz  rc_l3             ; break if ecx==0
    push   ebx
    call   RABBIT_next_state
    pop    eax
    
    xor    eax, eax
    cdq
    mov    edi, esp
    pushad
    ; for (i=0; i<4; i++) {
    ;   x.d[i] = c->w.x[i<<1];
    ; }
rc_l1:
    mov    ecx, [ebx+eax*8]
    mov    [edi+eax*4], ecx
    inc    eax
    cmp    al, 4
    jnz    rc_l1
    
    mov    esi, [ebx+1*4]    ; ebx = c->w.x[1]
    mov    ecx, [ebx+3*4]    ; ecx = c->w.x[3]
    mov    edx, [ebx+5*4]    ; edx = c->w.x[5]
    mov    ebp, [ebx+7*4]    ; ebp = c->w.x[7]
    
    ; x.d[0] ^= (c->w.x[5]>>16) ^ (c->w.x[3]<<16);
    ror    edx, 16       ; x5 >> 16
    mov    eax, ecx
    shl    eax, 16       ; x3 << 16
    mov    ax, dx
    xor    [edi+4*0], eax
    ; x.d[1] ^= (c->w.x[7]>>16) ^ (c->w.x[5]<<16);
    ror    ebp, 16
    mov    dx, bp
    xor    [edi+4*1], edx
    ; x.d[2] ^= (c->w.x[1]>>16) ^ (c->w.x[7]<<16);
    ror    esi, 16
    mov    bp, si
    xor    [edi+4*2], ebp
    ; x.d[3] ^= (c->w.x[3]>>16) ^ (c->w.x[1]<<16);
    ror    ecx, 16
    mov    si, cx
    xor    [edi+4*3], esi
    popad
    
    ; for (i=0; i<16 && inlen!=0; i++) {
    ;   *in++ ^= x.b[i];
    ;   inlen--;
    ; }
    mov    dl, 16            ; do 16 bytes or remaining
rc_l2:
    mov    al, [edi]         ; al = x.b[i]
    inc    edi
    xor    [esi], al         ; *in ^= al
    inc    esi               ; in++
    dec    edx               ; i--
    loopnz rc_l2             ; break if --len==0 or i==0
    jmp    rc_l0
rc_l3:
    popad                    ; free stack
    popad                    ; restore registers
    ret
    
    