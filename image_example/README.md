Image processing example
========================

This is an example of a proxy dedicated to serving dynamically resized and sharpened JPEG images.

It accepts HTTP queries with the following GET parameters:

- `width`: width of the image to serve, in pixels
- `height`: height of the image to serve, in pixels
- `sharpening`: opacity of the sharpening layer, `0` being transparent and `100` being completely opaque.

The proxy will load a remote image, then cache it, resize it, sharpen it and recompress it on the fly according to these parameters.

This demo can only serve a single image, whose URI is defined in the `image.h` file.

Image manipulations may require a lot of memory. If you run out of memory, try a smaller image.

## HTTP query example

The following query:

`https://.../width=640&height=400&sharpening=25`

will return the original image, resized to 640x400 pixerls, sharpened on a layer with 25% opacity.