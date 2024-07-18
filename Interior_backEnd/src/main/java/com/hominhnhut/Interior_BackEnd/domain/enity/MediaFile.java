package com.hominhnhut.WMN_BackEnd.domain.enity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Date;

@Entity
@Table(name = "media_files")
@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MediaFile {

    @Id
    String mediaFileID;

    String mediaFilePath;

    @Column(unique = true)
    String mediaFileName;
    String mediaFileType;
    Date createAt;
}
