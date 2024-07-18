import { useEffect, useState } from "react";
import {getListUserOverView,RemoveUserApi } from '../../Data/User/userApi.js'
import { getCountUser } from "../../Data/Role/RoleApi.js";
import CreateUser from "./Form/CreateUser.jsx";
import Swal from "sweetalert2";
import { RingLoader } from "react-spinners";
import UserCountCard from "./Card/UserCountCard.jsx";

const PAGE_SIZE = 5

function UserOverView() {

  const [pagePresent, setPagePresent] = useState(0)
  const [pageSize, setPageSize] = useState()
  const [roleData, setRoleData] = useState([])
  const [rolePresent, setRolePresent] = useState(0)
  const [hasCreate, setHasCreate] = useState(false);
  const [onLoad,setOnLoad] = useState(false);

  const [data,setData] = useState([])

  const setDataPage = async (pageNumber,Size,roleId) => {
        setOnLoad(true);
        const response = await getListUserOverView(pageNumber,Size,roleId);
        setData(response.content)
        setPageSize(response.totalPages)
        setOnLoad(false);
  }

  const refresh = async () => {
    console.log('Cập nhật lại trang');
    setOnLoad(true);
    await getCountUser().then(res => setRoleData(res)).then(() => {
      setDataPage(pagePresent,PAGE_SIZE,rolePresent)
    }).then(() => setOnLoad(false))
  }
  // Begin Trang
  useEffect(() => {
    refresh();
  }, [])

  // Hàm Next 
  const handleNext = () => {
    pagePresent === (pageSize -1) ? setPagePresent(0) : setPagePresent(pres => pres + 1)
  }

  // Hàm Prev
  const handlePrev = () => {
      pagePresent === 0 ? setPagePresent(pageSize - 1) : setPagePresent(pres => pres - 1)
  }
  
  // Sét RoleID
  const handleRole = (role) => {
        setRolePresent(role);
      setPagePresent(0)
  }

  // Bắt sự kiện thay đổi Page hoặc RoleId
  useEffect(() => {
    console.log(roleData);
      setDataPage(pagePresent,PAGE_SIZE,rolePresent);
      console.log("Cập nhật Data Page");
  },[pagePresent,rolePresent])

  const handleRemove = (idUser) => {
    RemoveUserApi(idUser).then(res => {
        if (res.status === 204) {
          Swal.fire({
            title : 'Xóa thành công',
            text : 'idUser : '+idUser,
            icon : 'success'
          }).then(() => refresh()).then(() => {
            if (data.length === 1) {
              console.log("gọi");
              handlePrev();
            }
          })
        }
        else {
            Swal.fire({
              title : 'Xóa thất bại',
              text : res.response.data.message + ' - '+idUser,
              icon : 'info'
            })
        }
    })
  }


  return (
    <div className="container-fluid">

{onLoad &&  <div className="my-loader-wrapper">
        <div className="my-loader">
        <RingLoader color="#36d7b7" size={200} loading={onLoad}/>
      </div>
       </div>}


      <div className="row gy-4">
        <UserCountCard handleRole={handleRole} roleData={roleData} setRoleData={setRoleData}/>
        <div className="col-md-3 col-sm-6 text-center d-flex align-items-end">
          <div className="create-user">
          <button className="btn btn-outline-light p-3 fw-bold text-uppercase" onClick={() => setHasCreate(
            prev => !prev
          )}>
            {hasCreate ? 'Ẩn Form Tạo User' : 'Hiện Form Tạo User'}</button>
          </div>
        </div>
        {hasCreate && <CreateUser refresh={refresh}/>}
        <div className="col-12">
        <table className="table table-hover text-center">
          <thead>
            <tr className="fw-bold text-danger">
              <th scope="col">STT</th>
              <th scope="col">Tài khoản</th>
              <th scope="col">Họ và Tên</th>
              <th scope="col">Email</th>
              <th scope="col">Giới tính</th>
              <th scope="col">Xóa</th>
            </tr>
          </thead>
          <tbody>
           {data.map(
              (user,index) => {
              return  <tr className="hoverTabel" key={index}>
                  <td>{index + 1}</td>
                  <td>{user.userName ?? 'Chưa có'}</td>
                  <td>{user.fullName ?? 'Chưa có'}</td>
                  <td>{user.email ?? 'Chưa có'}</td>
                  <td>{user.sex ? (user.sex ? 'Nam' : 'Nữ') : 'Chưa có'}</td>
                  <td>
                    <button className="btn btn-danger" onClick={() => handleRemove(user.userId)}>Xóa</button>
                  </td>
                </tr>
                }
              )}
          </tbody>
        </table>
        </div>  

        <div className="col-12 d-flex justify-content-end">
        <button className="btn btn-danger" onClick={() => handlePrev()}>Trước đó</button>
          <div className="numberPage mx-4 text-center m-2 fw-bold fs-5">
            <span className="pagePresent">{pagePresent + 1}</span>
            /
            <span className="pageSize">{pageSize}</span>
          </div>
          <button className="btn btn-success" onClick={() => handleNext()}>Tiếp theo</button>
        </div>
      
      </div>
    </div>

  );
}

export default UserOverView
