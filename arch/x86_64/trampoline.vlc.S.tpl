/*
 * Copyright 2018-2022 Yury Gribov
 * Copyright 2023 yinengy
 *
 * The MIT License (MIT)
 *
 * Use of this source code is governed by MIT license that can be
 * found in the LICENSE.txt file.
 */

  $visibility $sym
  .p2align 4
  .type $sym, %function
#ifndef IMPLIB_EXPORT_SHIMS
  .hidden $sym
#endif
  $version_directive
$sym:
  .cfi_startproc
  .cfi_def_cfa_offset 8  // Return address
  // Intel opt. manual says to
  // "make the fall-through code following a conditional branch be the likely target for a branch with a forward target"
  // to hint static predictor.
  pushq $$$number
  .cfi_adjust_cfa_offset 8
  call _${lib_suffix}_save_regs_and_resolve
  mov (%rsp), %rax  // fetch return value of the function
  addq $$8, %rsp
  .cfi_adjust_cfa_offset -8
