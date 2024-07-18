package com.hominhnhut.WMN_BackEnd.domain.enity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

@Entity
@Table(name = "users_profile")
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class UserProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String profileId;

    String profileFullName;

    Boolean profileSex;

    LocalDate profileBirth;

    @Column(unique = true)
    String profileEmail;

    @Column(unique = true)
    String profilePhone;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "imageId")
    MediaFile mediaFile;

    @OneToOne
    @JoinColumn(name = "userId")
    User user;
}
