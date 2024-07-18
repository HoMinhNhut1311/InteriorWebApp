
import { useContext, useState } from 'react';
import {  Outlet, useNavigate } from 'react-router-dom';
import Header from './Layout/Header.jsx';
import Sidebar from './Layout/Sidebar.jsx';
import 'bootstrap/dist/css/bootstrap.min.css';
import '/public/css/style.default.css'
import '/public/css/custom.css'
import UserContext from '../Context/userContext.jsx';

function AdminPage() {
  
  const navi = useNavigate();
  const {logout} = useContext(UserContext)
  const [active, setActive] = useState({
    numberPage : 1,
    title : '',
    des : 'Đây là trang chủ'
  })


  const handleLogOut = async (e) => {
    e.preventDefault();
    await logout();
    navi('/login')
  }
  
  const handleActive = (pageInfor) => {
      setActive(pageInfor)
  }

  const [isLite,setIsLite] = useState(false)
  const ToggleIsLite = () => {
        setIsLite(prev => !prev)
  }




  return (
    <div>
      <Header handleLogOut={handleLogOut} toggleLite={ToggleIsLite} isLite={isLite}/>
      <div className="d-flex align-items-stretch">
        {/* Sidebar Navigation*/}
       {!isLite ? <Sidebar handleActive={handleActive} active={active} isLite={isLite}/> : ''}
        <div className="page-content">

          {!isLite ? <div className="navigate">
            <div className='director'>
              <div className='director-title'>
                <span>{active.des}</span>
              </div>
            </div>
            <div className="path">
              <span className='path-main'> Trang chủ /
                <span className='path-text'>{active.title}</span>
              </span>
            </div>
          </div> : ''}
          <div className="content">
            <Outlet/> 
          </div>

        </div>

      </div>
    </div>


  );
}

export default AdminPage;