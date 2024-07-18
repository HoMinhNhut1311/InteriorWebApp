package com.hominhnhut.WMN_BackEnd.service.impl;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.hominhnhut.WMN_BackEnd.service.Interface.CloudinaryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CloudinaryServiceImpl implements CloudinaryService {

    private final Cloudinary cloudinary;

    public Map uploadImage(MultipartFile file)  {
        try{
            Map data = this.cloudinary.uploader().upload(file.getBytes(), Map.of());
            return data;
        }catch (IOException io){
            throw new RuntimeException("Image upload fail"+ io);
        }
    }

    @Override
    public Map uploadVideo(MultipartFile file) {
        try{
            Map data = this.cloudinary.uploader().uploadLarge(file.getBytes(),
                    ObjectUtils.asMap("resource_type", "video"));
            return data;
        }catch (IOException io){
            throw new RuntimeException("Image upload fail"+ io);
        }
    }

    public Map delete(String publicId) throws IOException {
        Map map = this.cloudinary.uploader().destroy(publicId,Map.of());
        return map;
    }
}
