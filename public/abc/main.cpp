#include <iostream>
#include <memory>
int main(){
	auto p = std::shared_ptr<int>();1111
	p.reset(nullptr);
	p = p;
}