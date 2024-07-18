package com.hominhnhut.WMN_BackEnd.exception;


import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;

@FieldDefaults(level = AccessLevel.PRIVATE)
@AllArgsConstructor
@Getter
public enum errorType {
    notFound(1000,"(Id) Đối tượng không tồn tại",HttpStatus.NOT_FOUND),
    notFoundRoleName(1000,"RoleName không tồn tại",HttpStatus.NOT_FOUND),
    unAuthorized(1001,"Tài khoản hoặc mật khẩu không chính xác",HttpStatus.UNAUTHORIZED),
    duplicateUnique(1002,"Thuộc tính đã tồn tại",HttpStatus.BAD_REQUEST),
    RoleNameIsNotTeacher(1003,"RoleName phải chứa Teacher",HttpStatus.BAD_REQUEST),
    CategoryIdIsNotExist(1004, "Category Id không tồn tại",HttpStatus.BAD_REQUEST),
    MediaFilePathNotExisxt(1005, "Media File Path không tồn tại",HttpStatus.BAD_REQUEST),
    CourseIdNotExist(1006, "Course Id không tồn tại",HttpStatus.BAD_REQUEST),
    userNameNotExist(1007, "Username không tồn tại", HttpStatus.UNAUTHORIZED),
    PasswordIsNotCorrect(1008, "Mật khẩu không chính xác",HttpStatus.UNAUTHORIZED),
    IsNotMyToken(1009, "Token không phải của chúng tôi",HttpStatus.BAD_REQUEST),
    ProductIdNotFound(1010, "Product Id khong ton tai",HttpStatus.BAD_REQUEST),
    NotFoundUsername(1011, "Username không tồn tại",HttpStatus.NOT_FOUND),
    notFoundProductName(1012,"san pham khong toan tai",HttpStatus.NOT_FOUND),
    ProductNameIsExist(1015,"Tên sản phẩm đã tồn tại",HttpStatus.BAD_REQUEST),
    EmailNotFound(1013, "Email khong ton tai",HttpStatus.NOT_FOUND),
    UsernameExisted(1014, "Username đã tồn tai",HttpStatus.BAD_REQUEST),
    RoleNameNotFound(1015, "Role Name khong ton tai",HttpStatus.NOT_FOUND),
    ;

    final int code;
    final String message;
    final HttpStatus httpStatus;
}