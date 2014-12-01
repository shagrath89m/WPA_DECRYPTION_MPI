#include <stdio.h>
#include <stdlib.h>
#include <include/mpi.h>
#include "wpa_decrypt.h"

int main(int argc, char **argv) 
{
    int st_dcr;
    
    MPI_Init(&argc,&argv);
    MPI_Comm_size(MPI_COMM_WORLD,&numprocs);
    MPI_Comm_rank(MPI_COMM_WORLD,&myid);

    tag=2098;
    st_dcr=wpa_decrypt(argc,argv);
    
    MPI_Finalize();
    return st_dcr;
}
