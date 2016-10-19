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
#include <unistd.h>
#include <mach-o/dyld_images.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>

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

typedef struct {
    int                in_use;
    mach_port_t        machTID;
    mach_msg_header_t* msg;
    mach_msg_size_t    receive_limit;
} thread_state;

#define NUM_STATES 1024
thread_state msg_states[NUM_STATES];
pthread_mutex_t states_lock;

thread_state* allocate_state(mach_port_t machTID) {
    for(int i = 0; i < NUM_STATES; i++) {
        if(msg_states[i].in_use == 0) {
            msg_states[i].in_use = 1;
            msg_states[i].machTID = machTID;

            return &(msg_states[i]);
        }
    }

    // no more states, why are there so many threads?!
    return NULL;
}

void deallocate_state(thread_state* state) {
    state->in_use = 0;
}

thread_state* find_state(mach_port_t machTID) {
    for(int i = 0; i < NUM_STATES; i++) {
        if(msg_states[i].in_use != 0 && msg_states[i].machTID == machTID) {
            return &(msg_states[i]);
        }
    }

    // not found
    return NULL;
}

void* hook_mach_msg_post(void* a1) {
    thread_state* state = NULL;
    mach_port_t machTID = pthread_mach_thread_np(pthread_self());

    pthread_mutex_lock(&states_lock);
    state = find_state(machTID);

    fprintf(output, "MACH: {\"tid\":%d, \"return\":\"0x%016X\", \"resp_msg\":\"", machTID, a1);

    if(state != NULL) {
        char* byt_str = (char*)state->msg;

        for(int i = 0; i < state->receive_limit; ++i) {
            fprintf(output, "%02X", *byt_str);

            byt_str++;
        }

        deallocate_state(state);
    } else {
        fprintf(output, "no state");
    }

    fprintf(output, "\"}\n");

    pthread_mutex_unlock(&states_lock);

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
    thread_state* state = NULL;

    pthread_mutex_lock(&states_lock);
    state = allocate_state(machTID);

    if(state != NULL) {
        state->msg = msg;
        state->receive_limit = receive_limit;
    }

    char* byt_str = (char*)msg;

    fprintf(output, "MACH: {\"msg\":\"");
    for(int i = 0; i < send_size; ++i) {
        fprintf(output, "%02X", *byt_str);

        byt_str++;
    }

    fprintf(output, "\", \"msg_option\":\"0x%016X\", \"notify\":%d, \"rcv_name\":%d, \"recv_msg_size\":%d, \"send_msg_size\":%d, \"timeout\":%d, \"tid\":%d}\n", option, notify, receive_name, receive_limit, send_size, timeout, machTID);

    pthread_mutex_unlock(&states_lock);

    return original_mach_msg;
}

typedef IMP (*p_cache_getImp)(Class cls, SEL sel);
p_cache_getImp c_cache_getImp = NULL;

void* hook_callback64_pre(id self, SEL op, void* a1, void* a2, void* a3, void* a4, void* a5) {
    // get the important bits: class, method
    char* classname = (char*) object_getClassName( self );
    Class cls = object_getClass(self);

    IMP cacheImp = NULL;

    if(cls != NULL && op != NULL) {
        cacheImp = c_cache_getImp(cls, op);
    }

    if(!cacheImp) {
        // not in cache, never been called, record the call.

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
        
        pthread_mutex_lock(&states_lock);

        // print some useful info.
        fprintf(output, "OBJC: %016x: [%s %s (", pthread_self(), classname, (char*)opname);

        int printParam = 0;
        for(int i = 0; i < namelen; i++) {
            if(opname[i] == ':') {
                printParam += 1;
            
                fprintf(output, "%p ", getParam(printParam, a1, a2, a3, a4, a5));
            }
        }

        fprintf(output, ")]\n");

        pthread_mutex_unlock(&states_lock);
    }

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

const struct mach_header* libobjc_dylib_base();
uint64_t findSymbol64(uint8_t* buffer, const int size, char* symbol, const int symsize);

// Work like an injected library.
__attribute__((constructor))
static void init_hook(int argc, const char **argv) {
    sleep(10);

    output = stderr;

    const struct mach_header* libobjc_base = libobjc_dylib_base();
    // static offset because symlook up was broken, would be nice to fix :)
    c_cache_getImp = (p_cache_getImp)((uint8_t*)libobjc_base) + 97792 + 0x4000;

    pthread_mutex_init(&states_lock, NULL);

    for(int i = i; i < NUM_STATES; i++) {
        msg_states[i].in_use = 0;
    }

    // objc_msgSend
    void* p_objc_msgSend = dlsym( RTLD_DEFAULT , "objc_msgSend" );

    if(p_objc_msgSend != NULL){
        original_msgSend = hook_function(p_objc_msgSend, objc_msgSend_trace);

        fprintf(output, "objc_msgSend function substrated from %p to %p, trampoline %p\n", p_objc_msgSend, objc_msgSend_trace, original_msgSend);
    } else {
        fprintf(output, "Failed to find objc_msgSend address\n");
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


// poor man's dlsym function, used to locate dlsym and dyld::loadFromMemory on /usr/lib/dyld.
//  this version of the procedure looks for 64bit symbols.
uint64_t findSymbol64(uint8_t* buffer, const int size, char* symbol, const int symsize) {
    // does not appear to be working with ios cached libraries unfortunately.

    // We assume that our target has a FAT file for dyld. Since we are targeting
    //  OSX/iOS, they will have dyld for 32/64 bit architectures in one file.
    int offset = 0;

    #if 0
    struct fat_header* fatheader = (struct fat_header*)buffer;
    struct fat_arch* archs = (struct fat_arch*)(buffer + sizeof(struct fat_header));

    // Iterate the FAT file architecture, looking for the architecture we want.
    for(int i = 0; i < fatheader->nfat_arch; ++i) {
        struct fat_arch* arch = &archs[i];
        struct mach_header_64* hdr = (struct mach_header_64*)(buffer + OSSwapBigToHostInt32(arch->offset));

        // Once we have found the 64-bit version, we assume this is the one we want.
        if(hdr->magic == MH_MAGIC_64) {
            // Fix up the buffer to allow the rest of the procedure to work on the 
            //  mach-o file.
            buffer = hdr;
            break;
        }
    }
    #endif

    // top of the Mach-o file is the header structure.
    struct mach_header_64* header = (struct mach_header_64*)buffer;

    // The structure must have a magic value that will match the 64bit architecture.
    if(header->magic != MH_MAGIC_64) {
        return -1;      
    }

    // we will need to skip the header.
    offset = sizeof(struct mach_header_64);

    // get the number of commands available in the header of the Mach-o.
    int ncmds = header->ncmds;

    // Iterate through all commands.
    while(ncmds--) {
        struct load_command * lcp = (struct load_command *)(buffer + offset);
        offset += lcp->cmdsize;

        // we are only interested in the symbol table command because it will enable us
        //  to find the symbol we are interested in.
        if(lcp->cmd == LC_SYMTAB) {
            struct symtab_command *symtab = (struct symtab_command *)lcp;

            // obtain the begining of the symbol table.
            struct nlist_64 *ns = (struct nlist_64 *)(buffer + symtab->symoff);
            char *strtable = buffer + symtab->stroff;

            // iterate through all symbol names.
            for (int j = 0; j < symtab->nsyms; ++j) {
                char* checkName = strtable + ns[j].n_un.n_strx;
                int isMatch = 1;

                // this is out custom strncmp which will look for the match.
                for(int i = 0; i < symsize && checkName[i] != '\0'; ++i) {
                    if(symbol[i] != checkName[i]) {
                        isMatch = 0;
                        break;
                    }
                }

                // Once matched we make sure that this isn't just a starts with match.
                if(isMatch && (checkName[symsize] == '\0')) {
                    // if it is a full match then return the address of the symbol.
                    return ns[j].n_value;
                }
            }
        }
    }

    // return zero if the symbol was not found.
    return 0;
}


//http://stackoverflow.com/a/33898317

const struct mach_header* libobjc_dylib_base() {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t) &dyld_info, &count) == KERN_SUCCESS) {
        struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) dyld_info.all_image_info_addr;
        struct dyld_image_info* info = (struct dyld_image_info*) infos->infoArray;

        for (int i=0; i < infos->infoArrayCount; i++) {
            if(strcmp(info[i].imageFilePath, "/usr/lib/libobjc.A.dylib") == 0) {
                printf("path: %p %s\n", info[i].imageLoadAddress, info[i].imageFilePath);

                return info[i].imageLoadAddress;
            }
        }
    } else {
        printf("Not success!\n");
    }

    return 0;
}
