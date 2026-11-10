#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct pixel {
    uint8_t r, g, b, a;
};

struct image {
    uint32_t      width;
    uint32_t      height;
    struct pixel *px;
};

/* File format: uint32 width, uint32 height, then width*height RGBA pixels. */
struct image *image_load(FILE *f)
{
    uint32_t hdr[2];

    if (fread(hdr, sizeof(uint32_t), 2, f) != 2)
        return NULL;

    struct image *img = malloc(sizeof(*img));
    if (img == NULL)
        return NULL;
    img->width = hdr[0];
    img->height = hdr[1];
    if (img->width == 0 || img->height == 0) {
        free(img);
        return NULL;
    }

    img->px = malloc(img->width * img->height * sizeof(struct pixel)); /* @@VULN@@ */
    if (img->px == NULL) {
        free(img);
        return NULL;
    }

    for (uint32_t y = 0; y < img->height; y++) {
        for (uint32_t x = 0; x < img->width; x++) {
            if (fread(&img->px[(size_t)y * img->width + x], sizeof(struct pixel), 1, f) != 1) {
                free(img->px);
                free(img);
                return NULL;
            }
        }
    }
    return img;
}

void image_free(struct image *img)
{
    if (img != NULL) {
        free(img->px);
        free(img);
    }
}
