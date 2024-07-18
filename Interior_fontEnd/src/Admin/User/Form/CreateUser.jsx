import { useEffect, useState } from "react";
import {createUser} from '../../../Data/User/userApi'
import Swal from "sweetalert2";
import { RingLoader } from "react-spinners";
import { getAllRole } from "../../../Data/Role/RoleApi";


function CreateUser({refresh}) {
    const [userCreate, setUserCreate] = useState({
        username : '',
        password : '',
        roleNames : []
    })

    const [roles, setRoles] = useState([])


    useEffect(() => {
        getAllRole().then(res => setRoles(res));
    },[])


    const [onLoad, setOnLoad] = useState(false);

    const handleRole = (role) => {
        console.log(userCreate);
        // Nếu role tồn tại thì gỡ
        const isChecked = userCreate.roleNames.includes(role);
        if (isChecked) {
                // Gỡ 
                const newRole = userCreate.roleNames.filter(r => r != role );
                setUserCreate({
                    ...userCreate,
                    roleNames : newRole
                })
        }
        else {
            setUserCreate({
            ...userCreate,
            roleNames : [...userCreate.roleNames,role]
        })
    }
    }

    const handleSubmit = (e) => {
        e.preventDefault();
        setOnLoad(true);
        createUser(userCreate).then((res) => {
            if (res.status === 200) {
                Swal.fire({
                    title : 'Tạo tài khoản thành công!',
                    text : `${res.data.userName} -- ${res.data.roleNames}`,
                    icon : 'success'
                }).then(() => {
                    setUserCreate({
                        username : '',
                        password : '',
                        roleNames : []
                    })
                    refresh()
                }
                )
            }
            else {
                const responseData = res.response.data;
                Swal.fire({
                    title : 'Tạo tài khoản thất bại!',
                    text : `Lỗi : ${responseData.message} + "
                    \nTrạng thái Sql : ${responseData.code}`,
                    icon : 'error'
                })
            }
        }).finally(() => {
            setOnLoad(false)
        })
    }
    
    return (
        <div className="createUser">

{onLoad &&  <div className="my-loader-wrapper">
        <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad}/>
      </div>
       </div>}

            <div className="form-group">
                <label htmlFor="username" className="form-label">Username</label>
                <input type="text" className="form-control" id="username" 
                    value={userCreate.username}
                    onChange={(e) => setUserCreate({
                        ...userCreate,
                        username : e.target.value
                    })}
                />
            </div>

            <div className="form-group">
                <label htmlFor="password" className="form-label">Password</label>
                <input type="password" className="form-control" id="password" 
                       value={userCreate.password}
                       onChange={(e) => setUserCreate({
                           ...userCreate,
                           password : e.target.value
                       })}
                />
            </div>
                <div className="my-2">
                <label htmlFor="" >Chức vụ</label>
                </div>
                {roles.map((role) => {
    return (
        <div className="form-check form-check-inline" key={role.roleName}>
            <input
                className="form-check-input"
                type="checkbox"
                id={role.roleName}
                value={role.roleName}
                checked={userCreate.roleNames.includes(role.roleName)}
                onChange={(e) => handleRole(e.target.value)}
            />
            <label className="form-check-label" htmlFor={role.roleName}>
                {role.roleName}
            </label>
        </div>
    );
})}

                <div className="d-flex justify-content-end">
                <button className="btn btn-primary mt-3 p-2" onClick={(e) => handleSubmit(e)}>Tạo mới</button>
                </div>

        </div>
    );
}

export default CreateUser;