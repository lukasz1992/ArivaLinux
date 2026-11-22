/*
 * vfork() for the no-MMU ALiLinux userland (linked into every program by the SDK compiler
 * wrapper, scripts/lib.sh make_cc; it replaces musl's vfork.o, which issues SYS_fork).
 *
 * musl's vfork() and fork() both use SYS_fork on MIPS, and the kernel cannot tell them
 * apart.  Without an MMU only the vfork behaviour can work (parent suspended until the
 * child execs or exits, child on the parent's stack), so the kernel's fork() fails
 * (-EINVAL) and vfork() asks for exactly that: clone(CLONE_VM | CLONE_VFORK | SIGCHLD), where SIGCHLD is 18 on MIPS (17 is SIGUSR2 here, unlike x86/ARM:
 * with 17 every child's exit would signal its parent with SIGUSR2 and kill a shell).
 *
 * A leaf, no stack frame, return address in $ra: the child returns into the caller on the
 * parent's stack, so nothing may live on it across the syscall.  Error handling as in musl:
 * -errno in $a0 for __syscall_ret.
 */
	.set	noreorder
	.text
	.globl	vfork
	.type	vfork, @function
vfork:
	.cpload	$25
	li	$2, 4120		/* __NR_clone */
	li	$4, 0x4112		/* CLONE_VM (0x100) | CLONE_VFORK (0x4000) | SIGCHLD (MIPS: 18 = 0x12) */
	move	$5, $0			/* no new stack: the child shares the parent's */
	move	$6, $0
	move	$7, $0
	syscall
	beqz	$7, 2f			/* no error: result as is */
	 move	$4, $2
	bltz	$2, 3f
	 nop
1:	negu	$4, $4			/* error: positive errno -> -errno */
2:	lw	$25, %call16(__syscall_ret)($28)
	jr	$25
	 nop
3:	b	1b
	 negu	$4, $2
	.size	vfork, .-vfork
