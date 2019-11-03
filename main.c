#include <libssh/libssh.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define NORMAL "\x1B[0m"
#define GREEN "\x1B[32m"
#define BUFFER_SIZE 16384

int gnosis_ls(ssh_session gno_ses, char *path)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(gno_ses);
    if (!channel) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    char command[PATH_MAX + 10];
    snprintf(command, sizeof(command), "ls %s", path);
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    char buff[BUFSIZ];
    int nbytes;

    nbytes = ssh_channel_read(channel, buff, sizeof(buff), 0);
    while (nbytes > 0)
    {
        if (fwrite(buff, 1, nbytes, stdout) != nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buff, sizeof(buff), 0);
    }

    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_OK;
}

int gnosis_get_file(ssh_session gno_ses, sftp_session sftp, char *source, char *destination)
{
    int access_type;
    sftp_file file;
    char buffer[BUFFER_SIZE];

    int nbytes, nwriteen, rc;
    int fd;

    access_type = O_RDONLY;
    file = stfp_open(sftp, source, access_type, 0);

    if (!file)
    {
        fprintf(stderr, "File couldn't be opened for reading: %s\n", ssh_get_error(gno_ses));
        return SSH_ERROR;
    }

    if (!destination)
    {
        char wd[strlen(source)];
        memset(wd, 0, sizeof(wd));

        int loc = 0;
        for (int i = (strlen(source) - 1); i > 0; i--)
        {
            if (source[i] == '/')
            {   
                loc = i + 1;
                break;
            }
        }
        if (loc)
        {
            for (int i = loc; i != strlen(source);i++)
            {
                strcat(wd, &source[i]);
            }
            wd[strlen(source) - loc] = '\0';
        }
        fd = open(wd, O_CREAT);
    } 
    else
    {
        fd = open(destination, O_CREAT);
    }
    
    if (fd < 0)
    {
        fprintf(stderr, "File couldn't be opened for writing: %s\n", strerror(errno));
        return SSH_ERROR;
    }
    
    while(1)
    {
        nbytes = sftp_read(file, buffer, sizeof(buffer));
        if (nbytes == 0)
        {
            break;
        }
        else if (nbytes < 0)
        {
            fprintf(stderr, "Error while reading file %s\n",ssh_get_error(gno_ses));
            return SSH_ERROR;
        }

        nwriteen = write(fd, buffer, nbytes);
        if (nwriteen != nbytes)
        {
            fprintf(stderr, "Error writing%s\n", strerror(errno));
            sftp_close(file);
            return SSH_ERROR;
        }
    }

    rc = sftp_close(file);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Couldn't close the source file: %s\n",ssh_get_error(gno_ses));
        return rc;
    }

    return SSH_OK;
}

int begin_sftp_session(ssh_session gno_ses)
{
    sftp_session sftp;
    int rc;

    sftp = sftp_new(session);
    if (!sftp)
    {
        fprintf(stderr, "Error allocating SFTP session%s\n", ssh_get_error(gno_ses));
        return SSH_ERROR;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session%s\n", sftp_get_error(sftp));
        sftp_free(sftp);
        return SSH_ERROR;   
    }

    sftp_free(sftp);
    return SSH_OK;
}


int gnosis_get(ssh_session gno_ses,ssh_scp scp)
{
    int rc;
    long size, permissions;
    char *buff, *filename, path[PATH_MAX];

    while(1)
    {
        rc = ssh_scp_pull_request(scp);
        switch (rc)
        {
            case SSH_SCP_REQUEST_EOF:
                return SSH_OK;

            case SSH_SCP_REQUEST_WARNING:
                fprintf(stderr,"Warning: %s\n", ssh_scp_request_get_warning(scp));
                break;

            case SSH_ERROR:
                fprintf(stderr, "Error: %s\n",ssh_get_error(gno_ses));
                return SSH_ERROR;

            case SSH_SCP_REQUEST_ENDDIR:
                chdir("..");
                //ssh_scp_accept_request(scp);
                break;

            case SSH_SCP_REQUEST_NEWDIR:
                filename = strdup(ssh_scp_request_get_filename(scp));
                permissions = ssh_scp_request_get_permissions(scp);
                //sprintf(path, "%s", filename);
                printf("Downloading directory =====> %s ", filename);
                mkdir(filename, permissions);
                chdir(filename);
                printf("\t\t[%sOK%s]\n", GREEN, NORMAL);
                free(filename);
                ssh_scp_accept_request(scp);
                break;

            case SSH_SCP_REQUEST_NEWFILE:
                size = ssh_scp_request_get_size(scp);
                printf("Size is %d\n",size);
                filename = strdup(ssh_scp_request_get_filename(scp));
                permissions = ssh_scp_request_get_permissions(scp);
                
                FILE *file;
                file = fopen(filename, "w+");
                if (!file)
                {
                    ssh_scp_deny_request(scp,"Unable to open");
                    fprintf(stderr, " %s: %s\n", filename, strerror(errno));
                    fclose(file);
                    break;
                }
        
                buff = malloc(size);
                printf("Size of buffer is %d\n", size);
                if (!buff)
                {
                    fprintf(stderr, "\nBuff memory allocation error.\n");
                    return SSH_ERROR;
                }
                
                if( ssh_scp_accept_request(scp) != SSH_OK)
                {
                    fprintf(stderr, "Error accepting request: %s\n", ssh_get_error(gno_ses));
                    break;
                }

                do
                {
                    rc = ssh_scp_read(scp, buff, size);
                    if (rc == SSH_ERROR)
                    {
                        fprintf(stderr, "Error receiving file data: %s\n", ssh_get_error(gno_ses));
                        break;
                    }
                    if (fwrite(buff, 1, size, file) != size)
                    {
                        perror("Error at writting to file: ");
                        break;
                    }
                    printf("ssh_scp_read got %d\n",rc);
                } while (rc != 0);
                 
                printf("Downloading file =====> %s with size %d bytes \t\t[%sOK%s]\n", filename, size,GREEN, NORMAL);
                fclose(file);
                free(filename);
                free(buff);
                break;
        }
    }
    return SSH_OK;
}

int gnosis_put(ssh_session gno_ses, ssh_scp scp, char *argv)
{
    int rc;
    char dirname_buffer[PATH_MAX];
    char filename_buffer[PATH_MAX];
    sprintf(dirname_buffer, "%s", argv);
    sprintf(filename_buffer,"%s", argv);
    struct stat object;
    stat(argv,&object);
    if(S_ISDIR(object.st_mode))
    {
        DIR *directory;
        struct dirent *dir;
        directory = opendir(argv);
        if (directory)
        {
            rc = ssh_scp_push_directory(scp, filename_buffer, S_IRWXU);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Can't create remote directory: %s\n", ssh_get_error(gno_ses));
                return rc;
            }
            printf("Uploading directory =====> %s\t\t[%sOK%s]\n", filename_buffer, GREEN, NORMAL);
            while (dir = readdir(directory))
            {
                if (dir->d_type == DT_DIR)
                {
                    if( !strcmp(dir->d_name,".") || !strcmp(dir->d_name,".."))
                    {
                        continue;
                    }
                    else
                    {
                        strcat(dirname_buffer,"/");
                        strcat(dirname_buffer,dir->d_name);
                        if(gnosis_put(gno_ses, scp, dirname_buffer) != SSH_OK)
                        {
                            return SSH_ERROR;
                        }
                        printf("Uploading directory =====> %s\t\t[%sOK%s]\n", dirname_buffer, GREEN, NORMAL);
                    }
                }
                else if (dir->d_type == DT_REG)
                {
                    sprintf(filename_buffer,"%s/%s", argv, dir->d_name);

                    FILE *file;
                    char *file_buff;
                    unsigned long file_len;

                    file = fopen(filename_buffer, "r+");
                    if (!file)
                    {
                        fprintf(stderr, "Unable to open %s: %s\n", filename_buffer, strerror(errno));
                        return SSH_ERROR;
                    }

                    fseek(file, 0, SEEK_END);
                    file_len = ftell(file);
                    fseek(file, 0, SEEK_SET);

                    file_buff = (char*)malloc(file_len+1);
                    if (!file_buff)
                    {
                        fprintf(stderr, "Memory allocation error\n");
                        fclose(file);
                        return SSH_ERROR;
                    }

                    fread(file_buff,file_len,1,file);
                    fclose(file);
                    rc = ssh_scp_push_file(scp, dir->d_name, file_len, S_IRUSR | S_IWUSR);
                    if (rc != SSH_OK)
                    {
                        fprintf(stderr, "Can't open remote file: %s\n",ssh_get_error(gno_ses));
                        return rc;
                    }
                    rc = ssh_scp_write(scp, file_buff, file_len);
                    if (rc != SSH_OK)
                    {
                        fprintf(stderr, "Can't write to remote file: %s\n", ssh_get_error(gno_ses));
                        return rc;
                    }
                    printf("Uploading file =====> %s\t\t[%sOK%s]\n", filename_buffer, GREEN, NORMAL);
                }
            }
        closedir(directory);
        }
    }
    else if(S_ISREG(object.st_mode))
    {
        FILE *file;
        char *file_buff;
        unsigned long file_len;

        file = fopen(argv, "rb");
        if (!file)
        {
            fprintf(stderr, "Unable to open %s\n", argv);
            return SSH_ERROR;
        }

        fseek(file, 0, SEEK_END);
        file_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        file_buff = (char*)malloc(file_len+1);
        if (!file_buff)
        {
            fprintf(stderr, "Memory allocation error\n");
            fclose(file);
            return SSH_ERROR;
        }

        fread(file_buff,file_len,1,file);
        fclose(file);
        rc = ssh_scp_push_file(scp, argv, file_len, S_IRUSR | S_IWUSR);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "Can't open remote file: %s\n",ssh_get_error(gno_ses));
            return rc;
        }
        rc = ssh_scp_write(scp, file_buff, file_len);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "Can't write to remote file: %s\n", ssh_get_error(gno_ses));
            return rc;
        }
        printf("Uploading file =====> %s\t\t[%sOK%s]\n", argv, GREEN, NORMAL);
    }
    return SSH_OK;
}

int into_library(ssh_session gno_ses, int write, char *argv)
{
    ssh_scp scp;
    int rc;
    switch (write)
    {
        case 2:

        case 0:
            scp = ssh_scp_new(gno_ses, SSH_SCP_READ | SSH_SCP_RECURSIVE, argv);
            break;
        case 1:
            scp = ssh_scp_new(gno_ses, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
            break;
        default:
            fprintf(stderr, "write should be 0 or 1\n");
            exit(1);
    }

    if (scp == NULL)
    {
        fprintf(stderr, "Error allocating scp session: %s\n",ssh_get_error(gno_ses));
        return SSH_ERROR;
    }

    rc = ssh_scp_init(scp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error creating scp session: %s\n",ssh_get_error(gno_ses));
        ssh_scp_free(scp);
        return rc;
    }
    if (write)
    {
        if (gnosis_put(gno_ses, scp, argv) == SSH_ERROR) 
        {
            fprintf(stderr, "Error at copying file%s\n");
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return SSH_ERROR;
        }
    }
    else
    {
        if (gnosis_get(gno_ses, scp) == SSH_ERROR) 
        {
            fprintf(stderr, "Error at getting file%s\n");
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return SSH_ERROR;
        }
    }
    
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}

int pubkey_verification(ssh_session gno_ses)
{
    int state, rc;
    size_t hash_len;
    ssh_key server_key;
    unsigned char *hash = NULL;
    char *hash_to_s;
    char buff[10];

    state = ssh_is_server_known(gno_ses);
    if (ssh_get_publickey(gno_ses, &server_key) == SSH_ERROR) // Deprecated, should be ssh_get_server_publickey()
    {
        printf("Error obtaining server pub key\n");
        return 1;
    }

    rc = ssh_get_publickey_hash(server_key, SSH_PUBLICKEY_HASH_SHA1, &hash, &hash_len);
    if (rc < 0)
    {
        fprintf(stderr, "Error obtaining hash from publickey%s\n",ssh_get_error(gno_ses));
        return 1;
    }
    switch(state)
    {
        case SSH_SERVER_KNOWN_OK:
            break;

        case SSH_SERVER_KNOWN_CHANGED:
            fprintf(stderr, "Host key for server changed to: \n");
            ssh_print_hexa("Public key hash",hash, hash_len);
            fprintf(stderr, "And attacker could be impersonating the server, do you still want to trust this hosts? Y/N (default N)\n");
            if (fgets(buff, sizeof(buff), stdin) == NULL)
            {
                free(hash);
                return 1;
            }
            if (strncasecmp(buff, "y", 1) != 0)
            {
                free(hash);
                return 1;
            }
            if (ssh_write_knownhost(gno_ses) == SSH_ERROR)
            {
                fprintf(stderr, "Error adding host: %s\n",ssh_get_error(gno_ses));
                free(hash);
                return 1;
            }
            break;

        case SSH_SERVER_FOUND_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to confuse your client into thinking the key does not exist\n");
            fprintf(stderr, "Quitting for security reasons\n");
            free(hash);
            return -1;

        case SSH_SERVER_FILE_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key, the file will be automatically created.\n");

        case SSH_SERVER_NOT_KNOWN:
            fprintf(stderr, "\nThe server is unknown. Do you want to trust the host key? Y/N (default N)\n");
            ssh_print_hexa("Public key hash",hash, hash_len);
            if (fgets(buff, sizeof(buff), stdin) == NULL)
            {
                free(hash);
                return 1;
            }
            if (strncasecmp(buff,"y",1) != 0)
            {
                free(hash);
                return 1;
            }
            if (ssh_write_knownhost(gno_ses) == SSH_ERROR)
            {
                fprintf(stderr, "Error adding host: %s\n",ssh_get_error(gno_ses));
                free(hash);
                return 1;
            }
            break;

        case SSH_SERVER_ERROR:
            fprintf(stderr, "Error: \n",ssh_get_error(gno_ses));
            free(hash);
            return 1;
    }
    free(hash);
    return 0;
}

int set_options(ssh_session gno_ses)
{
    char *host = "127.0.0.1";
    char *user = "user";
    int logs_verbosity = SSH_LOG_PROTOCOL;
    int rc;
    rc = ssh_options_set(gno_ses, SSH_OPTIONS_HOST, host);
    if (rc < 0)
    {
        fprintf(stderr, "Error at ssh_options_set host\n");
    }
    rc = ssh_options_set(gno_ses, SSH_OPTIONS_USER, user);
    if (rc < 0)
    {
        fprintf(stderr, "Error at ssh_options_set user\n");
    }
    /*
    rc = ssh_options_set(gno_ses, SSH_OPTIONS_LOG_VERBOSITY, &logs_verbosity);
    if (rc < 0)
    {
        fprintf(stderr, "Error at ssh_options_set logs\n");
    }
    */
}

int main(int argc, char **argv)
{
    int list;
    int write;
    char *list_path;
    switch(argc)
    {
        case 1:
            fprintf(stderr, "Usage: gnosis [ls/put/get] [directory|file]\n");
            exit(1);

        case 2:
            if (!strcmp("ls", argv[1]))
            {
                list = 1;
                list_path = ".";
                break;
            }

        case 3:
            if (!strcmp("ls", argv[1]))
            {
                list = 1;
                list_path = argv[2];
                break;
            }
            else if (!strcmp("get", argv[1]))
            {
                write = 0;
                break;
            }
            else if (!strcmp("put", argv[1]))
            {
                write = 1;
                break;
            }

        default:
            fprintf(stderr, "Usage: gnosis [ls/put/get] [directory|file]\n");
            exit(1);
    }

    int rc;
    ssh_session gnosis_session = ssh_new();

    if (gnosis_session == NULL)
    {
        exit(1);
    }

    set_options(gnosis_session);
    rc = ssh_connect(gnosis_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting: %s\n",ssh_get_error(gnosis_session));
        exit(1);
    }
    if(pubkey_verification(gnosis_session))
    {
        printf("Error at pubkey_verification\n");
        ssh_disconnect(gnosis_session);
        ssh_free(gnosis_session);
        exit(1);
    }
    
    int attempts = 0;
    for(int i = 0; i < 3; i++)
    {
        char *password = getpass("Password: ");
        rc = ssh_userauth_password(gnosis_session, NULL, password);
        if(rc != SSH_AUTH_SUCCESS)
        {
            fprintf(stderr, "Error in authentication: %s\n", ssh_get_error(gnosis_session));
            attempts++;
        }
        else
        {
            break;
        }
    }
    if(attempts == 3)
    {
        fprintf(stderr, "Too many attempts\n");
        printf("Quitting\n");
        ssh_disconnect(gnosis_session);
        ssh_free(gnosis_session);
        exit(1);
    }

    if (list)
    {
        gnosis_ls(gnosis_session, list_path);
        ssh_disconnect(gnosis_session);
        ssh_free(gnosis_session);
        exit(0);
    }
    
    into_library(gnosis_session, write, argv[2]);

    ssh_disconnect(gnosis_session);
    ssh_free(gnosis_session);
    exit(0);
}
