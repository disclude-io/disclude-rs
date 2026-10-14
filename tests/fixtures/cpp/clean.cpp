#include <cstdint>
#include <string>
#include <vector>

namespace geometry {

constexpr std::uint64_t kLimit = 1'000'000;
constexpr char kQuote = '"';

// A raw string holding quotes, a `//` and a backslash: one literal.
const char* kUsage = R"usage(Run "shape --area" // or: shape \help)usage";

template <typename T>
class Box {
 public:
  explicit Box(T side) : side_(side) {}
  T area() const { return side_ * side_; }

 private:
  T side_;
};

std::vector<double> areas(const std::vector<double>& sides) {
  std::vector<double> out;
  out.reserve(sides.size());
  for (double side : sides) {
    out.push_back(Box<double>(side).area());
  }
  return out;
}

}  // namespace geometry
