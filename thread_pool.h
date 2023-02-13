#include<iostream>
#include<queue>

using namespace std;

/*任务指针*/
typedef void (*handler_pt)(void*);

class epoll_server;

bool message_process(int fd);

class thread_pool{
    public:
    pthread_mutex_t mutex;//线程互斥锁
    pthread_cond_t condition;//线程条件锁
    pthread_t *thread;//线程池内线程指针

    int closed;//线程池结束标志位
    int started;//线程池内现存线程数

    int thread_num;//线程池线程总数
    int queue_size;//消息队列

    /*创建线程池，建立消息队列*/
    thread_pool *thread_pool_create(int thread_num, int queue_size);

    /*销毁线程池*/
    int thread_pool_destory(thread_pool *pool);

    /*线程池发布任务*/
    int thread_pool_post(thread_pool *pool, handler_pt func, int arg);

    /*等待线程池内所有线程销毁*/
    int wait_all_done(thread_pool *pool);

    /*释放线程池资源*/
    int thread_pool_free(thread_pool *pool);
};

/*线程池工作函数*/
void *thread_worker(void *arg);
