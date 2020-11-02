project('snapsnap', 'cpp',
  default_options: ['cpp_std=c++17'])

cmake = import('cmake')
pkg = import('pkgconfig')

unicorn_opts = cmake.subproject_options()
unicorn_opts.add_cmake_defines({'UNICORN_ARCH': 'x86', 'UNICORN_BUILD_SHARED': false})

fmt = subproject('fmt', default_options: ['default_library=static'])
unicorn = cmake.subproject('unicorn', options: unicorn_opts)

fmt_dep = fmt.get_variable('fmt_dep')
thread_dep = dependency('threads', required: true)
elf_dep = dependency('libelf', required: true)

# Unicorn includes all of its headers as systems. Which prevents us from using
# some header such as elf.h (because it is defined in qemu/include).
unicorn_lib = unicorn.dependency('unicorn')
unicorn_x86_lib = unicorn.dependency('x86_64_softmmu')

unicorn_dep = declare_dependency(
   dependencies: [unicorn_lib, unicorn_x86_lib],
)

snapsnap_sources = [
  'src/vm.cpp',
  'src/mmu.cpp',
  'src/loader_coredump.cpp',
  'src/loader_snapdump.cpp',
  'src/utility_user_regs.cpp',
  'src/inputdb.cpp',
  'src/bumpallocator.cpp'
]

snapsnap_headers = include_directories('include')

snapsnap_library = library('snapsnap', snapsnap_sources,
  include_directories: snapsnap_headers,
  dependencies: [thread_dep, unicorn_dep, fmt_dep, elf_dep])

snapsnap_dep = declare_dependency(link_with: snapsnap_library,
  include_directories: snapsnap_headers,
)

snapsnap_test_sources = [
  'src/main.cpp'
]

executable('snapsnap_test', snapsnap_test_sources,
  dependencies: [snapsnap_dep, fmt_dep])

subdir('tests')
