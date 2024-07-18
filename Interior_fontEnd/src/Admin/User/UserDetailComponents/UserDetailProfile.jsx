import { useEffect, useState } from "react";
import { validateProfile} from '../../../Data/User/ValidateUser'
import { UpdateProfile } from "../../../Data/User/userApi";
import Swal from "sweetalert2";

function UserDetailProfile({
    fullname, birth, email , phone, sex, profileId, userId,
    setDetailProfile
}) {
    const [profile, setProfile] = useState({
        fullname : '',
        birth : '',
        email : '',
        phone : '',
        sex : false,
        profileId : profileId
    })

    const [isChange, setIsChange] = useState(false)
    const [errFullname, setErrFullname] = useState('')
    const [errBirth, setErrBirth] = useState('')
    const [errEmail, setErrEmail] = useState('')
    const [errPhone, setErrPhone] = useState('')

    useEffect(() => {
        setProfile({
            fullname : fullname ?? '',
            birth : birth ?? '',
            email : email ?? '',
            phone : phone ?? '',
            sex : sex,
            profileId : profileId
        })
    },[fullname])

    useEffect(() => {
        if (profile.fullname === fullname
            && profile.birth === birth
            && profile.email === email
            && profile.phone === phone
        ) {
            setIsChange(false)
        }
        else {
            setIsChange(true)
        }
      
        const isValid = validateProfile(
            profile.fullname,setErrFullname,
            profile.birth,setErrBirth,
            profile.email,setErrEmail,
            profile.phone,setErrPhone,
        )
        setIsChange(isValid)
    },[profile.fullname,profile.birth,profile.email,profile.phone,profile.sex])

    const handleUpdate = () => {
        console.log("Cập nhật Profile");
        UpdateProfile(
            profile.profileId, profile.fullname, profile.sex,
            profile.birth, profile.email, profile.phone,
            userId
        ).then(res => {
           Swal.fire({
            title : "Cập nhật thành công",
            text: `Cập nhật vào lúc : ${new Date(Date.now()).toLocaleString()}`,
            icon : 'success'
           }).then(() => {
            setDetailProfile(profile)
            setIsChange(false)
           })
        }).catch(err => {
            Swal.fire({
                title : 'Update thất bại',
                icon : 'error'
            })
        })
    }



    return (
        <>
        <div className="title text-center mb-4">
            <h3 className="text-white">Hồ sơ</h3>
            <span className="text-success">id : {profile.profileId}</span>
            </div>
            <div className="row">

                <div className="form-group col-6 mb-3">
                    <label htmlFor="" className="form-label text-green-yellow">Họ và tên</label>
                    <input type="text" className="form-control" 
                        value={profile.fullname}
                        onChange={(e) => setProfile({
                            ...profile,
                            fullname : e.target.value
                        })}
                    />
                    <span className="text-danger">{errFullname}</span>
                </div>

                <div className="form-group col-6 mb-3">
                    <label htmlFor="" className="form-label text-green-yellow">Ngày Sinh</label>
                    <input type="date" className="form-control" 
                        value={profile.birth}
                        onChange={(e) => setProfile({
                            ...profile,
                            birth : e.target.value
                        })}
                    />
                    <span className="text-danger">{errBirth}</span>
                </div>

                <div className="form-group col-12 mb-3">
                    <label htmlFor="" className="form-label text-green-yellow">Email</label>
                    <input type="text" className="form-control" 
                        value={profile.email}
                        onChange={(e) => setProfile({
                            ...profile,
                            email : e.target.value
                        })}
                    />
                    <span className="text-danger">{errEmail}</span>
                </div>

                <div className="form-group col-12 mb-3">
                    <label htmlFor="" className="form-label text-green-yellow">Số điện thoại</label>
                    <input type="text" className="form-control" 
                        value={profile.phone}
                        onChange={(e) => setProfile({
                            ...profile,
                            phone : e.target.value
                        })}
                    />
                    <span className="text-danger">{errPhone}</span>
                </div>
                    <div className="form-group col-6 mb-3">
                        <label htmlFor="" className="text-green-yellow">Giới tính</label>

                        
                        <div className="form-check form-check-inline ms-3 mt-2">
                         <input type="radio" className="form-check-input" id="male" name="sex"
                                checked={profile.sex}
                                onChange={() => setProfile({
                                    ...profile,
                                    sex : true
                                })}
                         />
                        <label type="radio" className="form-check-label" htmlFor="male">Nam</label>
                    </div>

                    <div className="form-check form-check-inline">
                         <input type="radio" className="form-check-input" id="female" name="sex"
                            checked={!profile.sex}
                            onChange={() => setProfile({
                                ...profile,
                                sex : false
                            })}
                         />
                        <label type="radio" className="form-check-label" htmlFor="female">Nữ</label>
                    </div>
                    </div>

                    {isChange ? <button className="btn btn-outline-success fs-5 p-2" onClick={() => handleUpdate()}>Cập nhật</button> 
                         :   <button className="btn btn-warning fs-5 p-2">Chưa đủ điều kiện cập nhật</button>
                    } 
            </div>
        </>
    );
}

export default UserDetailProfile;