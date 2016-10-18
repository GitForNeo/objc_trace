#include <stdio.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <pthread.h>
#include <objc/message.h>
#include <objc/objc.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <pthread.h>

__attribute__((naked))
id objc_msgSend_trace(id self, SEL op) {
    __asm__ __volatile__ (
        "stp fp, lr, [sp, #-16]!;\n"
        "mov fp, sp;\n"

        /**
        * Store the value of all the parameter registers (x0-x8, q0-q7) so we can
        * restore everything to the initial state at the time of the actual function
        * call
        */
        "sub    sp, sp, #(10*8 + 8*16);\n"
        "stp    q0, q1, [sp, #(0*16)];\n"
        "stp    q2, q3, [sp, #(2*16)];\n"
        "stp    q4, q5, [sp, #(4*16)];\n"
        "stp    q6, q7, [sp, #(6*16)];\n"
        "stp    x0, x1, [sp, #(8*16+0*8)];\n"
        "stp    x2, x3, [sp, #(8*16+2*8)];\n"
        "stp    x4, x5, [sp, #(8*16+4*8)];\n"
        "stp    x6, x7, [sp, #(8*16+6*8)];\n"
        "str    x8,     [sp, #(8*16+8*8)];\n"

        "BL _hook_callback64_pre;\n"
        "mov x9, x0;\n"

        // Restore all the parameter registers to the initial state.
        "ldp    q0, q1, [sp, #(0*16)];\n"
        "ldp    q2, q3, [sp, #(2*16)];\n"
        "ldp    q4, q5, [sp, #(4*16)];\n"
        "ldp    q6, q7, [sp, #(6*16)];\n"
        "ldp    x0, x1, [sp, #(8*16+0*8)];\n"
        "ldp    x2, x3, [sp, #(8*16+2*8)];\n"
        "ldp    x4, x5, [sp, #(8*16+4*8)];\n"
        "ldp    x6, x7, [sp, #(8*16+6*8)];\n"
        "ldr    x8,     [sp, #(8*16+8*8)];\n"
        // Restore the stack pointer, frame pointer and link register
        "mov    sp, fp;\n"
        "ldp    fp, lr, [sp], #16;\n"

        "BR x9;\n"       // call the original
    );
}

__attribute__((naked))
id mach_msg_trace(id self, SEL op) {
    __asm__ __volatile__ (
        "stp fp, lr, [sp, #-16]!;\n"
        "mov fp, sp;\n"

        /**
        * Store the value of all the parameter registers (x0-x8, q0-q7) so we can
        * restore everything to the initial state at the time of the actual function
        * call
        */
        "sub    sp, sp, #(10*8 + 8*16);\n"
        "stp    q0, q1, [sp, #(0*16)];\n"
        "stp    q2, q3, [sp, #(2*16)];\n"
        "stp    q4, q5, [sp, #(4*16)];\n"
        "stp    q6, q7, [sp, #(6*16)];\n"
        "stp    x0, x1, [sp, #(8*16+0*8)];\n"
        "stp    x2, x3, [sp, #(8*16+2*8)];\n"
        "stp    x4, x5, [sp, #(8*16+4*8)];\n"
        "stp    x6, x7, [sp, #(8*16+6*8)];\n"
        "str    x8,     [sp, #(8*16+8*8)];\n"

        "BL _hook_mach_msg_pre;\n"
        "mov x9, x0;\n"

        // Restore all the parameter registers to the initial state.
        "ldp    q0, q1, [sp, #(0*16)];\n"
        "ldp    q2, q3, [sp, #(2*16)];\n"
        "ldp    q4, q5, [sp, #(4*16)];\n"
        "ldp    q6, q7, [sp, #(6*16)];\n"
        "ldp    x0, x1, [sp, #(8*16+0*8)];\n"
        "ldp    x2, x3, [sp, #(8*16+2*8)];\n"
        "ldp    x4, x5, [sp, #(8*16+4*8)];\n"
        "ldp    x6, x7, [sp, #(8*16+6*8)];\n"
        "ldr    x8,     [sp, #(8*16+8*8)];\n"
        
        "BLR x9;\n" // call the original
        "BL _hook_mach_msg_post;\n"

        // Restore the stack pointer, frame pointer and link register
        "mov    sp, fp;\n"
        "ldp    fp, lr, [sp], #16;\n"
               
        "RET;\n"
    );
}

void* original_msgSend = NULL;
void* original_mach_msg = NULL;
FILE* output = NULL;

void* getParam(int num, void* a1, void* a2, void* a3, void* a4, void* a5) {
    switch(num) {
        case 1: return a1;
        case 2: return a2;
        case 3: return a3;
        case 4: return a4;
        case 5: return a5;
    }
    
    return NULL;
}

void* hook_mach_msg_post(void* a1) {
    // TODO: make stateful to get the response message.
    mach_port_t machTID = pthread_mach_thread_np(pthread_self());

    fprintf(output, "{\"tid\":%d, \"return\":\"0x%016X\"}\n", machTID, a1);

    return a1;
}

void* hook_mach_msg_pre(mach_msg_header_t*            msg,
                     mach_msg_option_t             option,
                     mach_msg_size_t            send_size,
                     mach_msg_size_t        receive_limit,
                     mach_port_t             receive_name,
                     mach_msg_timeout_t           timeout,
                     mach_port_t                   notify) {

    mach_port_t machTID = pthread_mach_thread_np(pthread_self());

    char* byt_str = (char*)msg;

    fprintf(output, "{\"msg\":\"");
    for(int i = 0; i < send_size; ++i) {
        fprintf(output, "%02X", *byt_str);

        byt_str++;
    }

    fprintf(output, "\", \"msg_option\":\"0x%016X\", \"notify\":%d, \"rcv_name\":%d, \"recv_msg_size\":%d, \"send_msg_size\":%d, \"timeout\":%d, \"tid\":%d}\n", option, notify, receive_name, receive_limit, send_size, timeout, machTID);

    return original_mach_msg;
}

void* hook_callback64_pre(id self, SEL op, void* a1, void* a2, void* a3, void* a4, void* a5) {
    // get the important bits: class, method
    char* classname = (char*) object_getClassName( self );
    if(classname == NULL) {
        classname = "nil";
    }
    
    char* opname = (char*) op;
    int namelen = strlen(opname);
    int classlen = strlen(classname);
    
    if(classlen > 1024) {
        // something is wrong, we really shouldn't have such long names
        goto bail;
    }
    
    // print some useful info.
    fprintf(output, "%016x: [%s %s (", pthread_self(), classname, (char*)opname);

    int printParam = 0;
    for(int i = 0; i < namelen; i++) {
        if(opname[i] == ':') {
            printParam += 1;
        
            fprintf(output, "%p ", getParam(printParam, a1, a2, a3, a4, a5));
        }
    }

    fprintf(output, ")]\n");

   bail:
    return original_msgSend;
}

typedef uint32_t instruction_t;
typedef uint64_t address_t;

typedef struct {
    instruction_t i1_ldr;
    instruction_t i2_br;
    address_t jmp_addr;
} s_jump_patch;

__attribute__((naked))
void d_jump_patch() {
    __asm__ __volatile__(
        // trampoline to somewhere else.
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n" // place for jump address
        ".long 0;\n"
    );
}

s_jump_patch* jump_patch(){
    return (s_jump_patch*)d_jump_patch;
}

typedef struct {
    instruction_t     inst[4];    
    s_jump_patch jump_patch[5];
    instruction_t     backup[4];    
} s_jump_page;

__attribute__((naked))
void d_jump_page() {
    __asm__ __volatile__(
        // placeholder for original instructions
        "B INST1;\n"
        "B INST2;\n"
        "B INST3;\n"
        "B INST4;\n"

        // jump holder, this is the default case
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n" // place for jump address
        ".long 0;\n"

        // jump holder
        // this and following are instruction cases
        "INST1:;\n"
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n"
        ".long 0;\n"

        // jump holder
        "INST2:;\n"
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n"
        ".long 0;\n"

        // jump holder
        "INST3:;\n"
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n"
        ".long 0;\n"

        // jump holder
        "INST4:;\n"
        "ldr x16, #8;\n"
        "br x16;\n"
        ".long 0;\n"
        ".long 0;\n"

        // placeholder for original instructions
        //  above originals might get modified
        "B INST1;\n"
        "B INST2;\n"
        "B INST3;\n"
        "B INST4;\n"

    );
}

s_jump_page* jump_page() {
    return (s_jump_page*)d_jump_page;
}

void write_jmp_patch(void* buffer, void* dst) {
    s_jump_patch patch = *(jump_patch());

    patch.jmp_addr = (address_t)dst;

    *(s_jump_patch*)buffer = patch;
}

typedef struct {
    uint32_t offset   : 26;
    uint32_t inst_num : 6;
} inst_b;

typedef struct {
    uint32_t condition: 4;
    uint32_t reserved : 1;
    uint32_t offset   : 19;
    uint32_t inst_num : 8;
} inst_b_cond;

void check_branches(s_jump_page* t_func, instruction_t* o_func) {
    int use_jump_patch = 1;

    for(int i = 0; i < 4; i++) {
        address_t branch_offset = 0;
        address_t patch_offset = ((address_t)&t_func->jump_patch[use_jump_patch] - (address_t)&t_func->inst[i]) / 4;
        
        instruction_t inst = t_func->inst[i];
        inst_b*       i_b      = (inst_b*)&inst;
        inst_b_cond*  i_b_cond = (inst_b_cond*)&inst;

        if(i_b->inst_num == 0x5) {
            // unconditional branch

            // save the original branch offset
            branch_offset = i_b->offset;
            i_b->offset = patch_offset;

        } else if(i_b_cond->inst_num == 0x54) {
            // conditional branch

            // save the original branch offset
            branch_offset = i_b_cond->offset;
            i_b_cond->offset = patch_offset;
        }

        if(branch_offset > 0) {
            // put instruction back in
            t_func->inst[i] = inst;

            // set jump point into the original function, don't forget that it is PC relative
            t_func->jump_patch[use_jump_patch].jmp_addr = (address_t)( ((instruction_t*)o_func) + branch_offset + i);

            // use following patch next time.
            use_jump_patch++;
        }
    }
}

void* hook_function(void* original, void* replacement) {
    instruction_t* o_func = original;
    s_jump_page* t_func = (s_jump_page*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    mach_port_t self_task = mach_task_self();

    if(t_func == MAP_FAILED) {
        perror("Unable to allocate trampoline page");
        return NULL;
    }

    if(vm_protect(self_task, (vm_address_t)o_func, 4096, true, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS ||
       vm_protect(self_task, (vm_address_t)o_func, 4096, false, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        perror("Unable set PROT_READ | PROT_WRITE on original");
        return NULL;
    }

    //   Building the Trampoline
    *t_func = *(jump_page());
    // save first 4 32bit instructions
    //   original -> trampoline
    instruction_t* orig_preamble = (instruction_t*)o_func;
    for(int i = 0; i < 4; i++) {
        t_func->inst  [i] = orig_preamble[i];
        t_func->backup[i] = orig_preamble[i];
    }

    // Set the default case to return to the original 
    // function after preamble
    write_jmp_patch(&t_func->jump_patch[0], (o_func + 4));

    // check that we handle preable branches.
    check_branches(t_func, o_func);


    //   Modifying the original

    // in origninal function
    // set jump point target to the hook function
    write_jmp_patch(o_func, replacement);


    // set permissions to exec
    if(mprotect((void*)t_func, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("Unable to change trampoline permissions to exec");
        return NULL;
    }

    if(vm_protect(self_task, (vm_address_t)o_func, 4096, true, VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS ||
       vm_protect(self_task, (vm_address_t)o_func, 4096, false, VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
        perror("Unable set PROT_READ | PROT_EXEC on original");
        return NULL;
    }

    return t_func;
}

void* unhook_function(void* _jump_page) {
    s_jump_page* jump_page = (s_jump_page*)_jump_page;
    instruction_t* o_func = ((instruction_t*)(jump_page->jump_patch[0].jmp_addr)) - 4;

    for(int i = 0; i < 4; i++) {
        o_func[i] = jump_page->backup[i];
    }

    munmap(_jump_page, 4096);
}

// Work like an injected library.
__attribute__((constructor))
static void init_hook(int argc, const char **argv) {
    output = stderr;

    // objc_msgSend
    void* p_objc_msgSend = dlsym( RTLD_DEFAULT , "objc_msgSend" );

    if(p_objc_msgSend != NULL){
        original_msgSend = hook_function(p_objc_msgSend, objc_msgSend_trace);

        fprintf(output, "objc_msgSend function substrated from %p to %p, trampoline %p\n", p_objc_msgSend, objc_msgSend_trace, original_msgSend);
    } else {
        fprintf(output, "Failed to find objc_msgSend address");
    }


    // mach_msg
    void* p_mach_msg = dlsym( RTLD_DEFAULT , "mach_msg" );

    if(p_mach_msg != NULL){
        original_mach_msg = hook_function(p_mach_msg, mach_msg_trace);

        fprintf(output, "mach_msg function substrated from %p to %p, trampoline %p\n", p_mach_msg, mach_msg_trace, original_mach_msg);
    } else {
        fprintf(output, "Failed to find mach_msg address");
    }
}

__attribute__((destructor))
void clean_hook() {
    if(original_msgSend != NULL){
        unhook_function(original_msgSend);
    }

    if(original_mach_msg != NULL){
        unhook_function(original_mach_msg);
    }
}
