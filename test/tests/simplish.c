int check(int x)
{
    if((0xcafebabe^x)%17492 == 4583)
    {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) 
{
    return check(atoi(argv[1]));
}