project('snapsnap', 'cpp',
  default_options: ['cpp_std=c++17'])

cmake = import('cmake')

unicorn_opts = cmake.subproject_options()
unicorn_opts.add_cmake_defines({'UNICORN_ARCH': 'x86', 'UNICORN_BUILD_SHARED': false})

fmt = subproject('fmt', default_options: ['default_library=static'])
unicorn = cmake.subproject('unicorn', options: unicorn_opts)

fmt_dep = fmt.get_variable('fmt_dep')
unicorn_dep = unicorn.get_variable('cm_unicorn_dep')
unicorn_x86_dep = unicorn.get_variable('cm_x86_64_softmmu_dep') # Bit of a hack
thread_dep = dependency('threads')

snapsnap_sources = [
  'src/main.cpp'
]

snapsnap_headers = include_directories('include')

executable('snapsnap_test', snapsnap_sources,
  include_directories: snapsnap_headers,
  dependencies: [thread_dep, unicorn_dep, fmt_dep])
