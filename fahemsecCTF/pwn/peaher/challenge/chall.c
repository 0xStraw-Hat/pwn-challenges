#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 32
#define MAX_SIZE 0x200

void *chunks[MAX_CHUNKS];
size_t chunk_sizes[MAX_CHUNKS];

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
    puts("1. Create chunk");
    puts("2. Edit chunk");
    puts("3. View chunk");
    puts("4. Free chunk");
    puts("5. Exit");
    printf("> ");
}

int get_index() {
    int index;
    printf("Index: ");
    scanf("%d", &index);
    if (index < 0 || index >= MAX_CHUNKS) {
        puts("Invalid index!");
        return -1;
    }
    return index;
}

size_t get_size() {
    size_t size;
    printf("Size: ");
    scanf("%lu", &size);
    if (size == 0 || size > MAX_SIZE) {
        puts("Invalid size! (Max: 0x200)");
        return 0;
    }
    return size;
}

void create_chunk() {
    int index = get_index();
    if (index == -1) return;
    
    if (chunks[index] != NULL) {
        puts("Chunk already exists!");
        return;
    }
    
    size_t size = get_size();
    if (size == 0) return;
    
    chunks[index] = malloc(size);
    if (chunks[index] == NULL) {
        puts("Allocation failed!");
        return;
    }
    
    chunk_sizes[index] = size;
    
    printf("Chunk created at index %d\n", index);
}

void edit_chunk() {
    int index = get_index();
    if (index == -1) return;
    
    if (chunks[index] == NULL) {
        puts("Chunk doesn't exist!");
        return;
    }

    printf("Data: ");
    read(0, chunks[index], 128);
    
    puts("Chunk updated!");
}

void view_chunk() {
    int index = get_index();
    if (index == -1) return;
    
    printf("Chunk at index %d:\n", index);
    printf("%s\n", (char *)chunks[index]); 
}

void free_chunk() {
    int index = get_index();
    if (index == -1) return;
    
    if (chunks[index] == NULL) {
        puts("Chunk doesn't exist!");
        return;
    }
    
    free(chunks[index]);

    puts("Chunk freed!");
}

int main() {
    int choice;
    
    setup();
    
    puts("Welcome");
    puts("Can you exploit me?");
    
    while (1) {
        menu();
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                create_chunk();
                break;
            case 2:
                edit_chunk();
                break;
            case 3:
                view_chunk();
                break;
            case 4:
                free_chunk();
                break;
            case 5:
                puts("Goodbye!");
                exit(0);
            default:
                puts("Invalid choice!");
        }
    }
    
    return 0;
}