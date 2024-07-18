package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.enity.MediaFile;
import com.hominhnhut.WMN_BackEnd.service.Interface.MediaFileService;
import com.hominhnhut.WMN_BackEnd.service.impl.MediaFileServiceImpl;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/mediaFile")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class MediaFileController {

    MediaFileService mediaFileService;

    public MediaFileController(MediaFileServiceImpl myFileService) {
        this.mediaFileService = myFileService;
    }

    @PostMapping("/profile/{profileId}")
    public ResponseEntity<MediaFile> uploadImageToProfile(
            @RequestParam("image") MultipartFile file,
            @PathVariable("profileId") String profileID
    ) {
        MediaFile mediaFile = mediaFileService.uploadFileToProfile(file,profileID);
        return ResponseEntity.ok(mediaFile);
    }

    @PostMapping("/product/{productId}")
    public ResponseEntity<MediaFile> uploadImageToProduct (
            @RequestParam("image") MultipartFile file,
            @PathVariable("productId") String productId
    ) {
        MediaFile mediaFile = mediaFileService.uploadFileToProduct(file, productId);
        return ResponseEntity.ok(mediaFile);
    }




}
