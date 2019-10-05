#ifndef CPUCYCLES_H
#define CPUCYCLES_H


#ifdef DBENCH
#define DBENCH_START() unsigned long long time = cpucycles_start()
#define DBENCH_STOP(t) t += cpucycles_stop() - time - timing_overhead
#else
#define DBENCH_START()
#define DBENCH_STOP(t)
#endif

#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */
#ifdef SERIALIZE_RDC

static inline unsigned long long cpucycles_start(void) {
  const unsigned int ecx = (1U << 30) + 1;
  unsigned long long result;

  asm volatile("cpuid; movl %1,%%ecx; rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=&a" (result) : "r" (ecx) : "rbx", "rcx", "rdx");

  return result;
}

static inline unsigned long long cpucycles_stop(void) {
  const unsigned int ecx = (1U << 30) + 1;
  unsigned long long result, dummy;

  asm volatile("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax; movq %%rax,%0; cpuid"
    : "=&r" (result), "=c" (dummy) : "c" (ecx) : "rax", "rbx", "rdx");

  return result;
}

#else

static inline unsigned long long cpucycles_start(void) {
  const unsigned int ecx = (1U << 30) + 1;
  unsigned long long result;

  asm volatile("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

static inline unsigned long long cpucycles_stop(void) {
  const unsigned int ecx = (1U << 30) + 1;
  unsigned long long result;

  asm volatile("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

#endif
#else
#ifdef SERIALIZE_RDC

static inline unsigned long long cpucycles_start(void) {
  unsigned long long result;

  asm volatile("cpuid; rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rbx", "%rcx", "%rdx");

  return result;
}

static inline unsigned long long cpucycles_stop(void) {
  unsigned long long result;

  asm volatile("rdtscp; shlq $32,%%rdx; orq %%rdx,%%rax; mov %%rax,%0; cpuid"
    : "=r" (result) : : "%rax", "%rbx", "%rcx", "%rdx");

  return result;
}

#else

static inline unsigned long long cpucycles_start(void) {
  unsigned long long result;

  asm volatile("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

static inline unsigned long long cpucycles_stop(void) {
  unsigned long long result;

  asm volatile("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

#endif
#endif

unsigned long long cpucycles_overhead(void) {
  unsigned long long t0, t1, overhead = -1;
  unsigned int i;

  for(i = 0; i < 100000; ++i) {
    t0 = cpucycles_start();
    asm volatile("");
    t1 = cpucycles_stop();
    if(t1 - t0 < overhead)
      overhead = t1 - t0;
  }

  return overhead;
}

#endif
