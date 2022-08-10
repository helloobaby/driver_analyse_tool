提供分析内核或者其他驱动文件的框架。



只需要改user.cpp就可以了，src\example_user.cpp里有我自己写的一些例子。







##### 如何忽略让git忽略user.cpp,但是在commit的时候不删除云端和本地文件



cd driver_analyse_tool/src

git update-index --assume-unchanged "user.cpp"



例子项目:

https://github.com/my1forks/dump_driver
