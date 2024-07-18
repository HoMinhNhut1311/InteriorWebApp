export const validateLength = (value, minlength) => {
    if (!value || value.trim() === '' || value.length <= minlength) {
        return false; 
    }
    return true; 
};

function validateFullName(fullName,errFullname) {
    // Kiểm tra xem fullName có rỗng không
    if (!fullName.trim()) {
        errFullname('Họ và tên không được để trống');
        return false;
    }

    // Tách họ và tên từ chuỗi fullName
    const nameParts = fullName.trim().split(' ');

    // Kiểm tra xem có ít nhất hai phần (họ và tên) hay không
    if (nameParts.length < 2) {
        errFullname('Họ và tên ít nhất phải có 2 phần');
        return false;
    }

    // Kiểm tra xem các phần có chứa ký tự đặc biệt hay không
    const regex = /^[a-zA-ZÀ-ỹ\s]*$/;
    for (const part of nameParts) {
        if (!regex.test(part)) {
           errFullname('Họ và tên không được chứa kí tự đặc biệt');
           return false;
        }
    }

    errFullname('')
    return true;
}

function validateBirthDate(birthDate,errBirth) {
    // Kiểm tra xem birthDate có rỗng không
    if (!birthDate.trim()) {
        errBirth('Ngày sinh không được để trống');
        return false;
    }

    // Chuyển đổi ngày sinh từ chuỗi sang đối tượng Date
    const dob = new Date(birthDate);

    // Kiểm tra xem ngày sinh có hợp lệ không (không phải là một ngày không hợp lệ)
    if (isNaN(dob.getTime())) {
        errBirth('Ngày sinh không hợp lệ');
        return false;
    }

    // Tính tuổi dựa trên ngày sinh
    const today = new Date();
    let age = today.getFullYear() - dob.getFullYear();
    const monthDiff = today.getMonth() - dob.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())) {
        age--;
    }

    // Kiểm tra xem tuổi có lớn hơn 16 không
    if (age < 16) {
       errBirth('Bạn phải đủ 16 tuổi trở lên');
       return false;
    }
    errBirth('')
    return true;
}

function validateEmail(email,errorEmail) {
    if (!email.trim() ) {
        errorEmail('Email không được để trống')
    }

    // Biểu thức chính quy để kiểm tra địa chỉ email
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Sử dụng test() để kiểm tra định dạng của email
    if (!regex.test(email)) {
        errorEmail('Email không hợp lệ');
        return false;
    }
    errorEmail('')
    return true;

}

function validatePhoneNumber(phoneNumber,errorPhone) {
    if (!phoneNumber.trim() ) {
        errorPhone('Email không được để trống')
    }

    // Biểu thức chính quy để kiểm tra số điện thoại di động Việt Nam
    const regex = /^(0|\+84)(3[2-9]|5[25689]|7[06-9]|8[1-689]|9\d)\d{7}$/;

    // Sử dụng test() để kiểm tra định dạng của số điện thoại
    if (!regex.test(phoneNumber)) {
        errorPhone('Số điện thoại không hợp lệ');
        return false;
    }

    errorPhone('')
    return true;
}

export const validateProfile = (
    fullname,errFullname,birth,errBirth,email,errEmail,phone,errPhone
) => {
    const myCheck = [  validateFullName(fullname,errFullname)  ,
                    validateBirthDate(birth,errBirth) ,
                    validateEmail(email,errEmail)  ,
                    validatePhoneNumber(phone,errPhone) ]
    let valid = true;
    myCheck.forEach((check) => {
        if (!check) {
            valid = false;
        }
    })
    
    return valid;



}



export const validateUser = ({username,password,roleNames}, 
    setErrorUsername,setErrorPassword,setErrorRole,setIsChange
) => {
       
    // Check Username
    if (validateLength(username, 5)) {
        setErrorUsername('')
    }
    else {
        setIsChange(false)
        setErrorUsername('Username phải chứa hơn 5 ký tự')
    }

    // Check Password
    if (validateLength(password, 5)) {
        setErrorPassword('')
    }
    else {
        setIsChange(false)
        setErrorPassword('Password phải chứa hơn 5 ký tự')
    }

    // Check Role
    if (roleNames.length >= 1) {
        setErrorRole('')
    }
    else {
        setIsChange(false)
        setErrorRole('Phải chứa ít nhất 1 Role')
    }
}


