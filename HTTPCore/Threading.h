#ifndef __THREADING_H
#define __THREADING_H


void LockMutex(void *mutex);
void UnLockMutex(void *mutex);
void InitMutex(void *mutex);
void DeleteMutex(void *mutex);



#endif
