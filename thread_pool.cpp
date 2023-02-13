#include"thread_pool.h"

using namespace std;

queue<int> task_queue;

/*创建线程池*/
thread_pool *thread_pool::thread_pool_create(int thread_num, int queue_size){
    thread_pool *pool;

    //验证线程池参数
    if(thread_num <= 0 || queue_size <= 0){
        return NULL;
    }

    //分配内存
    pool = (thread_pool *)malloc(sizeof(*pool));
    if(pool == NULL){
        return NULL;
    }

    //线程池参数初始化
    pool->closed = 0;
    pool->started = 0;
    pool->thread_num = 0;
    pool->queue_size = queue_size;

    //线程池线程分配空间
    pool->thread = (pthread_t *)malloc(sizeof(pthread_t) * thread_num);
    if(pool->thread == NULL){
        free(pool);
        thread_pool_free(pool);
        return NULL;
    }

    //创建线程
    for(int i = 0; i < thread_num; i++){
        if(pthread_create(&pool->thread[i], NULL, thread_worker, (void*)pool) != 0){
            // 创建失败，释放空间
            thread_pool_free(pool);

            return NULL;
        }
        pool->started++;
        pool->thread_num++;
    }

    //线程池锁的初始化
    if(pthread_mutex_init(&(pool->mutex), NULL) == 0){
        printf("mutex sucess\n");
    }
    if(pthread_cond_init(&(pool->condition), NULL) == 0){
        printf("cond sucess\n");
    }

    return pool;        
}

/*线程池工作函数*/
void *thread_worker(void *arg){
    thread_pool *pool = (thread_pool *)arg;
    while(1){
        pthread_mutex_lock(&(pool->mutex));
        while(task_queue.size() == 0 && pool->closed == 0){//消息队列为空或线程池标志为未关闭，则循环
            printf("release\n");
            pthread_cond_wait(&(pool->condition), &(pool->mutex));
        }

        //线程池标志关闭，跳出循环，退出线程
        if(pool->closed == 1){
            break;
        }

        //获取消息队列的任务
        int task_fd = task_queue.front();
        task_queue.pop();
        pthread_mutex_unlock(&(pool->mutex));
        message_process(task_fd);
    }
    pool->started--;
    pthread_mutex_unlock(&(pool->mutex));
    pthread_exit(NULL);
    return NULL;
}

/*销毁线程池*/
int thread_pool::thread_pool_destory(thread_pool *pool){
    if(pool == NULL){
        return -1;
    }

    if(pthread_mutex_lock(&(pool->mutex)) != 0){
        return -1;
    }

    if(pool->closed == 1){
        return -1;
    }

    //关闭线程池标志
    pool->closed = 1;

    //广播所有线程结束
    if(pthread_cond_broadcast(&(pool->condition)) != 0 || pthread_mutex_lock(&(pool->mutex)) != 0){
        return -1;
    }

    //等待线程池内所有线程退出，释放资源
    wait_all_done(pool);
    thread_pool_free(pool);
    return 0;
}

/*线程池分布任务*/
int thread_pool::thread_pool_post(thread_pool *pool, handler_pt func, int arg){
    if(pthread_mutex_lock(&(pool->mutex)) != 0){//获取mutex锁
        return -1;
    }
    if(pool->closed == 1){//线程池标志退出
        pthread_mutex_unlock(&(pool->mutex));
        return -2;
    }
    if(pool->queue_size == task_queue.size()){//消息队列满
        pthread_mutex_unlock(&(pool->mutex));
        return -3;
    }
    //向消息队列添加任务，唤醒一个线程
    task_queue.push(arg);
    if(pthread_cond_signal(&(pool->condition)) != 0){
        pthread_mutex_unlock(&(pool->mutex));
        return -4;
    }
    pthread_mutex_unlock(&(pool->mutex));
    return 0;
}

/*等待线程池内所有线程销毁*/
int thread_pool::wait_all_done(thread_pool *pool){
    int i, ret = 0;
    for(i = 0; i < pool->thread_num; i++){
        if(pthread_join(pool->thread[i], NULL) != 0){
            ret = 1;
        }
    }
    return ret;
}

/*释放线程池资源*/
int thread_pool::thread_pool_free(thread_pool *pool){
    if(pool->thread != NULL){
        free(pool->thread);
        pool->thread = NULL;

        pthread_mutex_lock(&(pool->mutex));
        pthread_mutex_destroy(&(pool->mutex));
        pthread_cond_destroy(&(pool->condition));
    }
}