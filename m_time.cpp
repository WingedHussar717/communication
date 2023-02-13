#include"m_time.h"

using namespace std;

char *timeToString(){
    time_t a, b;
    time(&a);
    return ctime(&a);
}
int main(void){
    long a;
    time_t b;
    time(&b);
    a = b;
    printf("%ld %ld\n", a, b);
}