#ifndef UTILITY_HH
#define UTILITY_HH

#include <vector>
#include "unicorn/unicorn.h"

namespace ssnap
{

namespace utility
{

const std::vector<int>& get_user_regs_struct(uc_arch arch, uc_mode mode);

}

}


#endif
