package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.MediaFile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MediaFileRepository extends JpaRepository<MediaFile, String> {

    MediaFile findMediaFileByMediaFileName(String fileName);

    Optional<MediaFile> findMediaFileByMediaFilePath(String filePath);
}
