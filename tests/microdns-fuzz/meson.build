subdir('microdns-0.2.0')

fuzz_sources = [
  'fuzz.c'
]

fuzzer_sources = [
  'fuzzer.cpp'
]

thread_dep = dependency('threads')

fuzz = executable('fuzz', fuzz_sources,
  dependencies: [mdns_dep])

fuzzer = executable('snapsnap-fuzzer', fuzzer_sources,
  dependencies: [snapsnap_dep, fmt_dep, thread_dep])
