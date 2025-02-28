/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { styled } from '@superset-ui/core';
import { Menu as AntdMenu } from 'antd';

const MenuItem = styled(AntdMenu.Item)`
  > a {
    text-decoration: none;
  }

  &.ant-menu-item {
    height: ${({ theme }) => theme.gridUnit * 7}px;
    line-height: ${({ theme }) => theme.gridUnit * 7}px;
    a {
      border-bottom: none;
      transition: background-color ${({ theme }) => theme.transitionTiming}s;
      &:after {
        content: '';
        position: absolute;
        bottom: -3px;
        left: 50%;
        width: 0;
        height: 3px;
        opacity: 0;
        transform: translateX(-50%);
        transition: all ${({ theme }) => theme.transitionTiming}s;
        background-color: ${({ theme }) => theme.colors.primary.base};
      }
      &:focus {
        border-bottom: none;
        background-color: transparent;
        @media (max-width: 767px) {
          background-color: ${({ theme }) => theme.colors.primary.light5};
        }
      }
    }
  }

  &.ant-menu-item,
  &.ant-dropdown-menu-item {
    span[role='button'] {
      display: inline-block;
      width: 100%;
    }
    transition-duration: 0s;
  }
`;

const StyledNav = styled(AntdMenu)`
  line-height: 51px;
  border: none;
  background-color: #607d8b;

  & > .ant-menu-item,
  & > .ant-menu-submenu {
    vertical-align: inherit;
    &:hover {
      color: ${({ theme }) => theme.colors.grayscale.dark1};
    }
  }

  &:not(.ant-menu-dark) > .ant-menu-submenu,
  &:not(.ant-menu-dark) > .ant-menu-item {
    &:hover {
      border-bottom: none;
    }
  }

  &:not(.ant-menu-dark) > .ant-menu-submenu,
  &:not(.ant-menu-dark) > .ant-menu-item {
    margin: 0px;
  }

  & > .ant-menu-item > a {
    padding: ${({ theme }) => theme.gridUnit * 4}px;
    color: #ffffff;
  }

  & > .ant-menu-item > a:hover {
    color: #607d8b;
  }
`;

const StyledSubMenu = styled(AntdMenu.SubMenu)`
  color: ${({ theme }) => theme.colors.grayscale.dark1};
  border-bottom: none;
  .ant-menu-submenu-open,
  .ant-menu-submenu-active {
    color: #607d8b;
    background-color: ${({ theme }) => theme.colors.primary.light5};
    .ant-menu-submenu-title {
      border-bottom: none;
      margin: 0;
      &:after {
        opacity: 1;
        width: calc(100% - 1);
      }
    }
  }
  .ant-menu-submenu-title {
    position: relative;
    color: #ffffff;
    top: ${({ theme }) => -theme.gridUnit - 3}px;
    &:after {
      content: '';
      position: absolute;
      bottom: -3px;
      left: 50%;
      width: 0;
      height: 3px;
      opacity: 0;
      transform: translateX(-50%);
      transition: all ${({ theme }) => theme.transitionTiming}s;
      background-color: ${({ theme }) => theme.colors.primary.base};
    }
  }
  .ant-menu-submenu-arrow {
    top: 67%;
  }
  & > .ant-menu-submenu-title {
    color: #ffffff;
    padding: 0 ${({ theme }) => theme.gridUnit * 6}px 0
      ${({ theme }) => theme.gridUnit * 3}px !important;
    span[role='img'] {
      position: absolute;
      right: ${({ theme }) => -theme.gridUnit + -2}px;
      top: ${({ theme }) => theme.gridUnit * 5.25}px;
      svg {
        font-size: ${({ theme }) => theme.gridUnit * 6}px;
        color: #ffffff;
      }
    }
    & > span {
      position: relative;
      top: 7px;
    }
    &:hover {
      color: #ffffff;
    }
  }
`;

export declare type MenuMode =
  | 'vertical'
  | 'vertical-left'
  | 'vertical-right'
  | 'horizontal'
  | 'inline';

export const Menu = Object.assign(AntdMenu, {
  Item: MenuItem,
});

export const MainNav = Object.assign(StyledNav, {
  Item: MenuItem,
  SubMenu: StyledSubMenu,
  Divider: AntdMenu.Divider,
  ItemGroup: AntdMenu.ItemGroup,
});
