import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import UserDetailAccount from "./UserDetailComponents/UserDetailAccount";
import UserDetailProfile from "./UserDetailComponents/UserDetailProfile";
import UserDetailSecurity from "./UserDetailComponents/UserDetailSecurity";
import {selectById, UploadImageProFile} from '../../Data/User/userApi'
import Swal from "sweetalert2";
import { RingLoader } from "react-spinners";



function UserDetail() {

    const {idUser} = useParams()
    const [index, setIndex] = useState(0)
    const [fileImage, setFileImage] = useState();
    const [onLoad, setOnLoad] = useState(false);
    const [userDetail , setUserDetail] = useState(
        {
            userId: "",
            profileId: "",
            userName: "",
            password: "",
            fullName: "",
            sex: true,
            email: "",
            phone: "",
            birth: "",
            roleNames: [],
            mediaFile : {
                mediaFileID : "",
                mediaFilePath : "",
                mediaFileName : "",
                mediaFileType : "",
                createcreateAtAt : "",
            }
        }
    )

    const setDetailAccount = ({username, password, roleNames}) => {
            setUserDetail({
                ...userDetail,
                userName : username,
                password : password,
                roleNames : roleNames
            })
    }

    const setDetailProfile = ({fullname, birth, email, phone , sex}) => {
        setUserDetail({
            ...userDetail,
            fullName : fullname,
            sex : sex,
            email : email,
            phone : phone,
            birth : birth
        })
    }


    const handleNavigate = (indexContent) => {
            setIndex(indexContent)
    }

    useEffect(() => {
        setOnLoad(true);
       selectById(idUser).then(res => {
        setUserDetail(res)
       }).then(() => setOnLoad(false));
    },[userDetail.fullName])

    const handleUploadImage = () => {
            // Gửi Form
            if (fileImage === undefined) {
                    return Swal.fire({
                        title : 'Vui lòng chọn file trước khi cập nhật',
                        icon : 'question',
                    })
            }
            else {
                const fd = new FormData();
                fd.append("image",fileImage);
                setOnLoad(true);
                UploadImageProFile(userDetail.profileId, fd).then(res => console.log(res)).then(() => {
                    Swal.fire({
                        text : 'Cập nhật ảnh thành công',
                        icon : 'success'
                    })
                    setFileImage(null)
                    setOnLoad(false);
                })
            }

            
           
    }

    const handleInputChangeFile = (e) => {
        const file = e.target.files[0]
        setUserDetail({
            ...userDetail,
            mediaFile : {
                ...userDetail.mediaFile,
                mediaFilePath : URL.createObjectURL(file)
            }
        })
        setFileImage(file);
    }



    return (  
        <div className="userDetail">
            
            {onLoad &&  <div className="my-loader-wrapper">
        <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad}/>
      </div>
       </div>}

            <div className="row border-all userDetail-container">
                <div className="col-4 left-bar border-right d-flex flex-column p-0">
                    <div className="user-img text-center p-2 my-2">
                        {onLoad && <span>'Đang tải ảnh lên, chờ chút :).....'</span>}
                        {/* File Ảnh */}
                            <img src={userDetail.mediaFile ? userDetail.mediaFile.mediaFilePath
                                : 'https://res.cloudinary.com/dx1qqpmnt/image/upload/v1717086583/user_pikgqx.jpg'
                            } className="img-fluid" style={{width : 250, height : 120, 
                            }}/>
                        {/* File Ảnh */}
                        <div className="mt-3">
                                <input type="file" onChange={(e) => handleInputChangeFile(e)}/>
                              {fileImage &&   <button className="mt-2 btn btn-outline-primary"
                                 onClick={() => handleUploadImage()}>Cập nhật ảnh</button>}
                        </div>
                        <div className="user-fullname mt-1">
                                <span className="fw-bold text-white fs-4">{userDetail.fullName}</span>
                                <span className="text-warning" style={{fontSize : 14, display : 'block'}}>{userDetail.userId}</span>
                        </div>
                    </div>

                    <div className="nav mt-1">
                        <ul className="list-group w-100">
                            <li className="list-group-item p-3 text-white sidebar-nav border-bottom" onClick={() => handleNavigate(0)}>
                                <span className="ms-2 fw-bold ">Account</span>
                            </li>
                            <li className="list-group-item p-3 text-white sidebar-nav border-bottom" onClick={() => handleNavigate(1)}>
                                <span className="ms-2 fw-bold ">Profile</span>
                            </li>
                            <li className="list-group-item p-3 text-white sidebar-nav border-bottom" onClick={() => handleNavigate(3)}>
                                <span className="ms-2 fw-bold ">Security</span>
                            </li>
                        </ul>
                    </div>
                </div>

                <div className="col-8 info">
                    <div className="container my-4">
                    {index === 0 && <UserDetailAccount 
                    userId={idUser}  username={userDetail.userName}
                    password={userDetail.password} roleNames={userDetail.roleNames}
                    setDetailAccount={setDetailAccount}
                    />}

                     {index === 1 && <UserDetailProfile
                            fullname={userDetail.fullName} birth={userDetail.birth}
                            email={userDetail.email} phone={userDetail.phone}
                            sex={userDetail.sex} profileId={userDetail.profileId}
                            userId={userDetail.userId}
                            setDetailProfile={setDetailProfile}
                     />}
                     {index === 2 && <UserDetailSecurity/>}
                    </div>
                     
                </div>
            </div>
        </div>
    );
}

export default UserDetail;