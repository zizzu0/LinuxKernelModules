/*
* kallsyms_lookup_name undefined and finding not exported functions in the linux kernel
*
* zizzu 2020
*
* On kernels 5.7+ kallsyms_lookup_name is not exported anymore, so it is not usable in kernel modules.
* The address of this function is visible via /proc/kallsyms
* but since the address is randomized on reboot, hardcoding a value is not possible.
* A kprobe replaces the first instruction of a kernel function
* and saves cpu registers into a struct pt_regs *regs and then a handler
* function is executed with that struct as parameter.
* The saved value of the instruction pointer in regs->ip, is the address of probed function + 1.
* A kprobe on kallsyms_lookup_name can read the address in the handler function.
* Internally register_kprobe calls kallsyms_lookup_name, which is visible for this code, so,
* planting a second kprobe, allow us to get the address of kallsyms_lookup_name without waiting
* and then we can call this address via a function pointer, to use kallsyms_lookup_name in our module.
*
* example for _x86_64.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (--regs->ip);
  
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;
  
  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;
  
  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
    return ret;
  }
  
  pr_info("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);
  
  return ret;
}

static int m_init(void)
{
  int ret;
  
  pr_info("module loaded\n");
  
  ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
  if (ret < 0)
    return ret;
 
  ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
  if (ret < 0) {
    unregister_kprobe(&kp0);
    return ret;
  }
  
  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);
  
  pr_info("kallsyms_lookup_name address = 0x%lx\n", kln_addr);
  
  kln_pointer = (unsigned long (*)(const char *name)) kln_addr;
  
  pr_info("kallsyms_lookup_name address = 0x%lx\n", kln_pointer("kallsyms_lookup_name"));
  
  return 0;
}

static void m_exit(void)
{
  pr_info("module unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zizzu");

EXPORT_SYMBOL(kln_pointer);
