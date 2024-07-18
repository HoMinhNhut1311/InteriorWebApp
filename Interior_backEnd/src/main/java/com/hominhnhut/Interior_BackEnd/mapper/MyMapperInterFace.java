package com.hominhnhut.WMN_BackEnd.mapper;

public interface MyMapperInterFace<R,E,P> {

    E mapFromRequest(R R);

    P mapToResponese(E e);


    E mapNewProvider(E e,E eUpdate);
}
