CXX=g++
CXXO=g++ -c

CXXLIB=g++ -shared

CXXTARGET=ShellAPI.cpp
CXXOUTOBJ=shell.o
CXXOUTLIB=libshell.a

CXXLANGSTANDART=17

CXXAPP=main.cpp
CXXAPPNAME=tunnel_netshell

lib:
	$(CXXO) $(CXXTARGET) -o $(CXXOUTOBJ) -pthread -std=gnu++$(CXXLANGSTANDART) -v
	ar rcs $(CXXOUTLIB) $(CXXOUTLIB)

tunnel:
	$(CXX) -L. -I. $(CXXAPP) -o $(CXXAPPNAME) -lshell

clean:
	rm shell.o libshell.a