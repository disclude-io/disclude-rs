#pragma once

class Widget {
 public:
  int size() const { return size_; }

 private:
  int size_ = 0;
};
