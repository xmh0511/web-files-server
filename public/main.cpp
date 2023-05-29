#include <iostream>
#include <memory>
int main(){
	auto p = std::shared_ptr<int>();
	p.reset(nullptr);
	p = p;
}