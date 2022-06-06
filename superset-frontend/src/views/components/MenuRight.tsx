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
import React from 'react';
import { MainNav as Menu } from 'src/components/Menu';
import { t, styled /* , css, SupersetTheme */ } from '@superset-ui/core';
import Icons from 'src/components/Icons';

import {
  RightMenuProps,
} from './types';

export const dropdownItems = [
  {
    label: t('SQL query'),
    url: '/superset/sqllab?new=true',
    icon: 'fa-fw fa-search',
    perm: 'can_sqllab',
    view: 'Superset',
  },
  {
    label: t('Chart'),
    url: '/chart/add',
    icon: 'fa-fw fa-bar-chart',
    perm: 'can_write',
    view: 'Chart',
  },
  {
    label: t('Dashboard'),
    url: '/dashboard/new',
    icon: 'fa-fw fa-dashboard',
    perm: 'can_write',
    view: 'Dashboard',
  },
];

/* const versionInfoStyles = (theme: SupersetTheme) => css`
  padding: ${theme.gridUnit * 1.5}px ${theme.gridUnit * 4}px
    ${theme.gridUnit * 4}px ${theme.gridUnit * 7}px;
  color: ${theme.colors.grayscale.base};
  font-size: ${theme.typography.sizes.xs}px;
  white-space: nowrap;
`;
*/

const StyledDiv = styled.div<{ align: string }>`
  display: flex;
  flex-direction: row;
  justify-content: ${({ align }) => align};
  align-items: center;
  margin-right: ${({ theme }) => theme.gridUnit}px;
  .ant-menu-submenu-title > svg {
    top: ${({ theme }) => theme.gridUnit * 5.25}px;
  }
`;

const StyledAnchor = styled.a`
  padding-right: ${({ theme }) => theme.gridUnit}px;
  padding-left: ${({ theme }) => theme.gridUnit}px;
`;

const { SubMenu } = Menu;

const RightMenu = ({
  align,
  settings,
  navbarRight,
  isFrontendRoute,
}: RightMenuProps) => (
  <StyledDiv align={align}>
    <Menu mode="horizontal">
      <SubMenu title="Settings" icon={<Icons.TriangleDown iconSize="xl" />}>
        {!navbarRight.user_is_anonymous && [
          <Menu.Divider key="user-divider" />,
          <Menu.ItemGroup key="user-section" title={t('User')}>
            <Menu.Item key="logout">
              <a href={navbarRight.user_logout_url}>{t('Logout')}</a>
            </Menu.Item>
          </Menu.ItemGroup>,
        ]}
      </SubMenu>
    </Menu>
    {navbarRight.user_is_anonymous && (
      <StyledAnchor href={navbarRight.user_login_url}>
        <i className="fa fa-fw fa-sign-in" />
        {t('Login')}
      </StyledAnchor>
    )}
  </StyledDiv>
);
export default RightMenu;
