package com.hominhnhut.WMN_BackEnd.service.Interface;


import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

public interface CloudinaryService {

    Map uploadImage(MultipartFile file);

    Map uploadVideo(MultipartFile file);

    Map delete(String publicId) throws IOException;
}

